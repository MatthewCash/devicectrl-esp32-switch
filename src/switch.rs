use defmt::{info, warn};
use devicectrl_common::{
    DeviceId, DeviceState,
    device_types::switch::SwitchState,
    protocol::simple::{
        DeviceBoundSimpleMessage, ServerBoundSimpleMessage,
        esp::{TransportChannels, TransportEvent},
    },
    updates::AttributeUpdate,
};
use esp_hal::gpio::Output;

use crate::log_error;

#[embassy_executor::task]
pub async fn app_task(
    switch_pin: &'static mut Output<'static>,
    transport: &'static TransportChannels,
) {
    loop {
        match transport.incoming.receive().await {
            TransportEvent::Connected => {
                info!("Connected to server!");

                // This isn't required, but its nice to tell the server our initial state
                transport
                    .outgoing
                    .send(ServerBoundSimpleMessage::UpdateNotification(
                        devicectrl_common::UpdateNotification {
                            device_id: DeviceId::from(crate::DEVICE_ID).unwrap(),
                            reachable: true,
                            new_state: DeviceState::Switch(SwitchState {
                                power: switch_pin.is_set_high(),
                            }),
                        },
                    ))
                    .await;
            }
            TransportEvent::Error(err) => {
                log_error(&err);
            }
            TransportEvent::Message(DeviceBoundSimpleMessage::UpdateCommand(update)) => {
                if update.device_id.as_str() != crate::DEVICE_ID {
                    warn!(
                        "Received update command for different device {}!",
                        update.device_id.as_str()
                    );
                    continue;
                }

                let AttributeUpdate::Power(new_state) = update.update else {
                    warn!("Received unsupported attribute update, ignoring");
                    continue;
                };

                info!("Setting switch power to [{}]", new_state.power);

                if new_state.power {
                    switch_pin.set_high();
                } else {
                    switch_pin.set_low();
                }

                transport
                    .outgoing
                    .send(ServerBoundSimpleMessage::UpdateNotification(
                        devicectrl_common::UpdateNotification {
                            device_id: DeviceId::from(crate::DEVICE_ID).unwrap(),
                            reachable: true,
                            new_state: DeviceState::Switch(SwitchState {
                                power: new_state.power,
                            }),
                        },
                    ))
                    .await;
            }
            TransportEvent::Message(DeviceBoundSimpleMessage::StateQuery { device_id }) => {
                if device_id.as_str() != crate::DEVICE_ID {
                    warn!(
                        "Received state query for different device {}!",
                        device_id.as_str()
                    );
                    continue;
                }

                transport
                    .outgoing
                    .send(ServerBoundSimpleMessage::UpdateNotification(
                        devicectrl_common::UpdateNotification {
                            device_id,
                            reachable: true,
                            new_state: DeviceState::Switch(SwitchState {
                                power: switch_pin.is_set_high(),
                            }),
                        },
                    ))
                    .await;
            }
            _ => {}
        }
    }
}
