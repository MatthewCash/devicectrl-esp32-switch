#![no_std]
#![no_main]

extern crate alloc;

use alloc::string::ToString;
use anyhow::Error;
use core::{net::SocketAddrV4, str::FromStr};
use defmt::{error, println};
use defmt_rtt as _;
use devicectrl_common::protocol::simple::esp::{TransportChannels, transport_task};
use embassy_executor::Spawner;
use embassy_net::{Runner, Stack, StackResources, StaticConfigV4};
use embassy_time::{Duration, Timer};
use esp_backtrace as _;
use esp_hal::{
    clock::CpuClock,
    ecc::Ecc,
    gpio::{Level, Output, OutputConfig},
    peripherals,
    rng::{Rng, Trng},
    sha::Sha,
    timer::timg::TimerGroup,
};
use esp_hal_embassy::main;
use esp_wifi::{EspWifiController, wifi::WifiDevice};
use esp32_ecdsa::CryptoContext;
use heapless::Vec;
use p256::{
    PublicKey, SecretKey,
    pkcs8::{DecodePrivateKey, DecodePublicKey},
};

use crate::{switch::app_task, wifi::wifi_connection};

mod switch;
mod wifi;

const DEVICE_ID: &str = env!("DEVICE_ID");

macro_rules! mk_static {
    ($t:ty,$val:expr) => {{
        static STATIC_CELL: static_cell::StaticCell<$t> = static_cell::StaticCell::new();
        #[deny(unused_attributes)]
        let x = STATIC_CELL.uninit().write(($val));
        x
    }};
}

pub fn log_error(err: &Error) {
    error!("Error: {}", err.to_string().as_str());
    println!("Caused by:");

    err.chain().skip(1).enumerate().for_each(|(i, cause)| {
        println!("   {}: {}", i, cause.to_string().as_str());
    })
}

pub const SERVER_PUBLIC_KEY: &[u8] = include_bytes!(env!("SERVER_PUBLIC_KEY_PATH"));
pub const PRIVATE_KEY: &[u8] = include_bytes!(env!("PRIVATE_KEY_PATH"));

#[main]
async fn main(spawner: Spawner) {
    let peripherals = esp_hal::init(esp_hal::Config::default().with_cpu_clock(CpuClock::_80MHz));

    esp_alloc::heap_allocator!(size: 72 * 1024);

    let mut rng = Rng::new(peripherals.RNG);

    let timer1 = TimerGroup::new(peripherals.TIMG1);
    esp_hal_embassy::init(timer1.timer0);

    // enable internal antenna
    Output::new(peripherals.GPIO3, Level::Low, OutputConfig::default());
    Timer::after(Duration::from_millis(100)).await;
    Output::new(peripherals.GPIO14, Level::Low, OutputConfig::default());

    let timer0 = TimerGroup::new(peripherals.TIMG0);
    let wifi_init = &*mk_static!(
        EspWifiController<'static>,
        esp_wifi::init(timer0.timer0, rng).unwrap()
    );

    let (controller, interfaces) = esp_wifi::wifi::new(wifi_init, peripherals.WIFI).unwrap();

    let config = embassy_net::Config::ipv4_static(StaticConfigV4 {
        address: env!("IP_CIDR").parse().unwrap(),
        gateway: None,
        dns_servers: Vec::new(),
    });

    let seed = (rng.random() as u64) << 32 | rng.random() as u64;

    let (stack, runner) = embassy_net::new(
        interfaces.sta,
        config,
        mk_static!(StackResources<3>, StackResources::<3>::new()),
        seed,
    );

    let stack = mk_static!(Stack<'_>, stack);
    let runner = mk_static!(Runner<'_, WifiDevice<'_>>, runner);

    let switch_pin = mk_static!(
        Output<'_>,
        Output::new(peripherals.GPIO18, Level::Low, OutputConfig::default())
    );

    let crypto = CryptoContext {
        sha: Sha::new(peripherals.SHA),
        ecc: Ecc::new(peripherals.ECC),
        trng: Trng::new(unsafe { peripherals::RNG::steal() }, peripherals.ADC1), // should be safe as we don't use RNG after this
        secret_key: SecretKey::from_pkcs8_der(PRIVATE_KEY).expect("Failed to decode secret key"),
        server_public_key: PublicKey::from_public_key_der(SERVER_PUBLIC_KEY)
            .expect("Failed to decode server public key"),
    };

    let transport = mk_static!(TransportChannels, TransportChannels::new());

    let device_id =
        devicectrl_common::DeviceId::from(DEVICE_ID).expect("Failed to create device id");

    let server_addr = SocketAddrV4::from_str(env!("SERVER_ADDR")).expect("Invalid server address");

    spawner.spawn(wifi_connection(controller)).unwrap();
    spawner.spawn(net_task(runner)).unwrap();
    spawner
        .spawn(transport_task(
            stack,
            server_addr,
            transport,
            device_id,
            crypto,
        ))
        .unwrap();
    spawner.spawn(app_task(switch_pin, transport)).unwrap();
}

#[embassy_executor::task]
async fn net_task(runner: &'static mut Runner<'static, WifiDevice<'static>>) {
    runner.run().await
}
