# VirusTotalAnalyzer

VirusTotalAnalyzer is an [AutoPkg](https://autopkg.github.io/autopkg/) processor to query downloaded files from the [VirusTotal](https://www.virustotal.com) database. It is designed to be used as a post processor for AutoPkg.


# Installing

Clone this repo to any of the folders included in AutoPkg's search path or use the `autopkg repo-add` command. This repo includes a stub recipe which lets AutoPkg find the processor.

    autopkg repo-add https://github.com/hjuutilainen/autopkg-virustotalanalyzer.git

To check your installation, run `autopkg list-recipes` and verify that `VirusTotalAnalyzer` stub recipe is included in the list.

The following is _not_ required: If you want to provide your own VirusTotal API key, register for an account at [https://www.virustotal.com](https://www.virustotal.com). Then go to the "My API Key" page, copy the key and run:

    defaults write com.github.autopkg VIRUSTOTAL_API_KEY <your_api_key_here>


# Using VirusTotalAnalyzer

Once installed and visible to AutoPkg, you can include the processor in an AutoPkg run by running:

    autopkg run -v --post "io.github.hjuutilainen.VirusTotalAnalyzer/VirusTotalAnalyzer" <recipes_to_run>

If you need to disable VirusTotalAnalyzer for a single recipe, you can set the `VIRUSTOTAL_DISABLED` key to true to exclude it from future runs. The key should be set in the Input section of the override recipe. For example:

```
<dict>
    <key>Identifier</key>
    <string>local.my.override.recipe</string>
    <key>Input</key>
    <dict>
        <key>VIRUSTOTAL_DISABLED</key>
        <true />
        <key>NAME</key>
        <string>my_private_package</string>
    </dict>
    <key>ParentRecipe</key>
    <string>com.some.other.recipe</string>
</dict>
```


# Configurable options

By default, VirusTotalAnalyzer only scans new downloads. To always scan:

    defaults write com.github.autopkg VIRUSTOTAL_ALWAYS_REPORT -bool true

To automatically submit files that VirusTotal did not yet know about (files smaller than 400MB will be submitted):

    defaults write com.github.autopkg VIRUSTOTAL_AUTO_SUBMIT -bool true

To change the maximum file size for auto-submitting (default is 419430400 which equals 400MB):

    defaults write com.github.autopkg VIRUSTOTAL_AUTO_SUBMIT_MAX_SIZE -int <bytes>

To use your own VirusTotal API key:

    defaults write com.github.autopkg VIRUSTOTAL_API_KEY <your_api_key>

Since the VirusTotal API is rate limited, it might be useful to add some sleep time (the default is 15):

    defaults write com.github.autopkg VIRUSTOTAL_SLEEP_SECONDS -int <seconds>

