# Sigma2Elastic
Simple PowerShell script that translates Sigma rules to Elastic Security/ELK detection rules.
The main difference between this script and other automated solutions, like [Uncoder](https://uncoder.io/), is that here you get an `ndjson` file that you can directly upload as a Rule fully configured.

### The translator
This script is based on [sigmac](https://github.com/SigmaHQ/sigma/tree/master/tools) and not in the newer [sigma-cli](https://github.com/SigmaHQ/sigma-cli). Once this last is more mature I'll change this.

### The parser
The parser has been slightly modified from the original one to match the out of the box index names. Could differ from others. Feel free to modify it.

### No case sensitive
The biggest headache was to make queries no case sensitive. After many tries I decided to use the regex syntax available in Lucene query language. So queries will be like `[Nn][Oo][Cc][Aa][Ss][Ee]`.
In order to help the reading of the queries I added them in no regex format in the investigation tab
![Example](https://i.imgur.com/B86zH4R.png)

### Errors
Automated translation of the Sigma rules is not going to be perfect. Always test!

