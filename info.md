[![](https://img.shields.io/github/release/ollo69/ha_asuswrt_custom/all.svg?style=for-the-badge)](https://github.com/ollo69/ha_asuswrt_custom/releases)
[![hacs_badge](https://img.shields.io/badge/HACS-Custom-41BDF5.svg?style=for-the-badge)](https://github.com/hacs/integration)
[![](https://img.shields.io/github/license/ollo69/ha_asuswrt_custom?style=for-the-badge)](LICENSE)
[![](https://img.shields.io/badge/MAINTAINER-%40ollo69-red?style=for-the-badge)](https://github.com/ollo69)

# AsusWrt Custom HA integration

Home Assistant custom integration for use with AsusWRT router.

This integration is just for test purpose with the scope of testing the HTTP library [PyAsusWrt](https://github.com/ollo69/pyasuswrt).
This new library implement Router communication based on native AsusWrt API based on HTTP(s) protocol.<br/>
Final objective is to implement this communication method in native AsusWRT Home Assistant integration 
(see [PR #71899](https://github.com/home-assistant/core/pull/71899) )

## Installation

Integration can be installed using `HACS`, using the link `https://github.com/ollo69/ha_asuswrt_custom` to add it to your 
`HACS` custom repositories.

As alternative integration can be manually installed copying the folder `asuswrt_custom` inside the `custom_components` folder of your 
HA configuration directory.

## Configuration

After install, you can setup this integration from tha HA integration page. Please remember to remove the native `AsusWRT`
integration before configuring this one.
