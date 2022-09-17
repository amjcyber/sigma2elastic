# Sigma2Elastic
Simple PowerShell script that translates Sigma rules to Elastic Security/ELK detection rules.

### The parser
The parser has been slightly modified from the original one to match the out of the box index names. Could differ from others. Feel free to modify it.

### No case sensitive
The biggest headache was to make queries no case sensitive. After many tries I decided to use the regex syntax available in Lucene query language. So queries will be like `[Nn][Oo][Cc][Aa][Ss][Ee]`.
In order to help the reading of the queries I added them in no regex format in the investigation tab
![Example](https://i.imgur.com/B86zH4R.png)

