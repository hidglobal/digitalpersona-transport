# About

HID DigitalPersona WebSdk (2023 version). Transport layer.

# Changes

* Configurator session is now a private member and can be accessed with public async function configurator.getSessionStorageData().
* configurator.ensureLoaded() will throw an error instead of returning object with error member.