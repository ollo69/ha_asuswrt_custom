# AsusWrt Custom HA integration

Home Assistant custom integration for use with AsusWRT router.

This integration is just for test purpose with the scope of testing the HTTP library [PyAsusWrt](https://github.com/ollo69/pyasuswrt).
This new library implement Router comunication based on native AsusWrt API based on HTTP(s) protocol.

Integration must be manually installed copying the folder `asuswrt_custom` inside the `custom_components` folder of your 
HA configuration directory.

After install, you can setup this integration from tha HA integration page. Please remember to remove the native `AsusWRT`
integration before configuring this one.
