use alloc::{vec, vec::Vec};
use anyhow::{Context, Result, anyhow, bail};
use core::{net::SocketAddrV4, str::FromStr};
use defmt::{error, info};
use devicectrl_common::{
    DeviceId, DeviceState, DeviceStateUpdate, UpdateNotification,
    device_types::switch::SwitchState,
    protocol::simple::{DeviceBoundSimpleMessage, SIGNATURE_LEN, ServerBoundSimpleMessage},
};
use embassy_net::{Stack, tcp::TcpSocket};
use embassy_time::{Duration, Timer};
use embedded_io_async::Read;
use esp_hal::gpio::Output;

use crate::crypto::{CryptoContext, ecdsa_sign, ecdsa_verify};
use crate::{DEVICE_ID, log_error};

#[embassy_executor::task]
pub async fn connection_task(
    stack: &'static Stack<'static>,
    switch_pin: &'static mut Output<'static>,
    mut crypto: CryptoContext<'static>,
) {
    loop {
        Timer::after(Duration::from_secs(5)).await;
        info!("Reconnecting to server...");

        if let Err(err) = open_connection(stack, switch_pin, &mut crypto).await {
            log_error(&err.context("Failed to handle server loop"));
        }
    }
}

async fn open_connection(
    stack: &'static Stack<'_>,
    switch_pin: &mut Output<'static>,
    crypto: &mut CryptoContext<'_>,
) -> Result<()> {
    let mut rx_buffer = [0u8; 4096];
    let mut tx_buffer = [0u8; 4096];

    let mut socket = TcpSocket::new(*stack, &mut rx_buffer, &mut tx_buffer);

    socket.set_keep_alive(Some(Duration::from_secs(60)));
    socket
        .connect(SocketAddrV4::from_str(env!("SERVER_ADDR")).expect("Invalid server address"))
        .await
        .map_err(|e| anyhow!("failed to connect: {:?}", e))?;

    send_identify_message(&mut socket).await?;

    info!("Connected to server!");

    loop {
        let mut len_buf = [0u8; size_of::<u32>()];
        if socket
            .read(&mut len_buf)
            .await
            .map_err(|err| anyhow!("size recv: {:?}", err))?
            != size_of::<u32>()
        {
            bail!("Length delimiter is not a u32!")
        }

        handle_message(
            &mut socket,
            u32::from_be_bytes(len_buf) as usize,
            switch_pin,
            crypto,
        )
        .await?;
    }
}

#[allow(clippy::too_many_arguments)]
async fn handle_message(
    socket: &mut TcpSocket<'_>,
    message_len: usize,
    switch_pin: &mut Output<'static>,
    crypto: &mut CryptoContext<'_>,
) -> Result<()> {
    let mut buf = vec![0u8; message_len];
    socket
        .read_exact(&mut buf)
        .await
        .map_err(|err| anyhow!("data recv: {:?}", err))?;

    let sig: &[u8; SIGNATURE_LEN] = &buf
        .get(..SIGNATURE_LEN)
        .context("message is not long enough for signature")?
        .try_into()?;

    let data = &buf
        .get(SIGNATURE_LEN..message_len)
        .context("message is not long enough")?;

    if !ecdsa_verify(crypto, data, sig).context("ecdsa verification failed")? {
        bail!("signature does not match!")
    }

    let message: DeviceBoundSimpleMessage = serde_json::from_slice(data)?;
    match message {
        DeviceBoundSimpleMessage::UpdateCommand(update) => {
            if update.device_id.as_str() != DEVICE_ID {
                bail!("Update notification does not match this device id!")
            }

            update_state(switch_pin, &update.change_to)?;

            let state = query_state(switch_pin);
            send_state_update(socket, state, crypto).await?;
        }
        DeviceBoundSimpleMessage::StateQuery { device_id } => {
            if device_id.as_str() != DEVICE_ID {
                bail!("State query notification does not match this device id!")
            }

            let state = query_state(switch_pin);
            send_state_update(socket, state, crypto).await?;
        }
        _ => error!("Unknown command received!"),
    }

    Ok(())
}

fn update_state(switch_pin: &mut Output<'_>, requested_state: &DeviceStateUpdate) -> Result<()> {
    let DeviceStateUpdate::Switch(new_state) = requested_state else {
        bail!("Requested state is not a switch state!")
    };

    if let Some(state) = new_state.power {
        info!("Setting switch power to [{}]", state);

        match state {
            true => switch_pin.set_high(),
            false => switch_pin.set_low(),
        }
    }

    Ok(())
}

fn query_state(switch_pin: &mut Output<'_>) -> DeviceState {
    DeviceState::Switch(SwitchState {
        power: switch_pin.is_set_high(),
    })
}

async fn send_state_update(
    socket: &mut TcpSocket<'_>,
    state: DeviceState,
    crypto: &mut CryptoContext<'_>,
) -> Result<()> {
    let message = ServerBoundSimpleMessage::UpdateNotification(UpdateNotification {
        device_id: DeviceId::from(DEVICE_ID).map_err(|err| anyhow!(err))?,
        reachable: true,
        new_state: state,
    });

    send_message(socket, crypto, &message).await
}

async fn send_identify_message(socket: &mut TcpSocket<'_>) -> Result<()> {
    let mut data = serde_json::to_vec(&ServerBoundSimpleMessage::Identify(
        DeviceId::from(DEVICE_ID).map_err(|e| anyhow!(e))?,
    ))?;

    data.splice(0..0, data.len().to_be_bytes());

    socket
        .write(&data)
        .await
        .map_err(|err| anyhow!("{:?}", err))?;

    Ok(())
}

async fn send_message(
    socket: &mut TcpSocket<'_>,
    crypto: &mut CryptoContext<'_>,
    message: &ServerBoundSimpleMessage,
) -> Result<()> {
    let payload = serde_json::to_vec(message)?;
    let sig = ecdsa_sign(crypto, &payload).context("ecdsa signing failed")?;

    let total_len = (sig.len() + payload.len()) as u32;
    let mut data = Vec::with_capacity(size_of::<u32>() + total_len as usize);

    data.extend_from_slice(&total_len.to_be_bytes());
    data.extend_from_slice(&sig);
    data.extend_from_slice(&payload);

    socket
        .write(&data)
        .await
        .map_err(|err| anyhow!("{:?}", err))?;

    Ok(())
}
