# Email from Typo Squat Domin Received

## Description
This query detects the receipt of an email from a domain which mimics your own. Ripped from https://github.com/Bert-JanP/Hunting-Queries-Detection-Rules/blob/main/Office%20365/Email%20-%20TyposquattedEmailRecieved.md

```KQL
let Domain = tolower("yourdomainhere.com"); //Alter to include the domain you are interested in
let UnicodeDomain = unicode_codepoints_from_string(Domain);
let TypoSquatMin = 0.75;
let TypoSquatMax = 0.99; // If set to 1.0 it equals the domain.
EmailEvents
| where EmailDirection == "Inbound"
| extend SenderDomainUnicode = unicode_codepoints_from_string(tolower(SenderFromDomain))
| extend TypoSquadPercentage = jaccard_index(UnicodeDomain, SenderDomainUnicode)
| where TypoSquadPercentage between (TypoSquatMin .. TypoSquatMax)