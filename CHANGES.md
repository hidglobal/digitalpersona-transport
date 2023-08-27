# About

HID DigitalPersona WebSdk 2023 version.

DigitalPersona Web SDK (DP WebSDK) is a Windows service and a user agent application running 
locally on a user device and providing access to authentication devices like fingerprint readers,
smartcard readers etc. These devices are not directly accessible from Javascript running in a browser.

# Breaking changes

* **ifvisible** module was removed as it was not used by WebSdk and available as [npm packeage](https://github.com/serkanyersen/ifvisible.js).

* WebChannelClientImpl method *setReconnectTimer*() renamed to *startReconnectTimer*()
* WebChannelClientImpl method *resetReconnectTimer*()  renamed to *stopReconnectTimer*()

* WebChannelClientImpl *WebChannelClientImpl.fireConnectionFailed*() method will not attempt to reconnect if connection failed. 
  We fire event (with WebChannelClientImpl.onConnectionFailed) to client so client should decide to re-try establish connection.
  If code is used from serviceWokers then there is no window object to check if window is active.

```ts
    const client: WebChannelClientImpl = new WebChannelClientImpl();

    client.onConnectionFailed = () => {
        if (window.parent.parent.document.hasFocus()) {
            client.setReconnectTimer();
        }
    }
```
    The call client.setReconnectTimer() will try reconnect to server tree times.

* In previous version *WebChannelClientImpl* subscribed to blur and focus events in contructor. 
  When event happend WebChannelClientImpl was fiering *sdk.focusChanged* custom event.
  The new version of the WebSdk no longer tracks window focus events.
  If necessary, this can be done on the client side.

  ```ts
      const client: WebChannelClientImpl = new WebChannelClientImpl();
      listenFocusBlurEvents();

      function listenFocusBlurEvents() {
        window.parent.parent.addEventListener("blur", function () {
            client.resetReconnectTimer();
            notifyFocusChanged(false);
        });
        window.parent.parent.addEventListener("focus", function () {
            notifyFocusChanged(true);
        });
      }

      client.onConnectionSucceed = () => {
          if (window.parent.parent.document.hasFocus()) {
              notifyFocusChanged(true);
          } else {
              notifyFocusChanged(false);
          }
      }

      function notifyFocusChanged(isFocused: boolean) {
          if (client.isConnected()) {
              client.sendData(JSON.stringify({ type: 'sdk.focusChanged', data: isFocused, }));
          }
      }

  ```

# Minor changes
* Remove unsed WebSdk.Promise. This was not used for a log time.
* Private variable WebSdk renamed to envSdk. WebSdk name was used for everything.
* Remove property 'path' from WebChannelClient. It's comming from user already and is duplicate of user information
* WebSdk.IWebChannelClient.sendDataBin type is (data: number[]) => void; not (data: ArrayBuffer) => void (see AESEncryption())
