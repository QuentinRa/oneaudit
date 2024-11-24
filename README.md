<div align="center">

![LOGO](.github/dalle_logo.png)

[![GitHub](https://img.shields.io/github/license/QuentinRa/oneaudit)](LICENSE)
[![GitHub issues closed](https://img.shields.io/github/issues-closed/QuentinRa/oneaudit?color=%23a0)](https://github.com/QuentinRa/oneaudit/issues)
[![GitHub pull requests closed](https://img.shields.io/github/issues-pr-closed/QuentinRa/oneaudit?color=%23a0)](https://github.com/QuentinRa/oneaudit/pulls)
[![GitHub commit activity](https://img.shields.io/github/commit-activity/m/QuentinRa/oneaudit)](https://github.com/QuentinRa/oneaudit)
</div>

This tool is intended for legitimate open-source intelligence (OSINT) purposes, such as research and security assessments. Users are responsible for ensuring that their use of this tool complies with all applicable laws and regulations in their jurisdiction. We strongly encourage users to respect individuals' privacy and to refrain from using this tool for any malicious activities, including harassment or unauthorized access to personal data. By using this tool, you agree to act ethically and responsibly, understanding the potential legal implications of your actions.

WIP

* Clean censored passwords
* Recursive search based on new emails
* Handle domain aliases

## SocOSINT

### LinkedIn OSINT

✍️ Get name, birthdate, LinkedIn profile URL, professional and personal emails.

You can use this module to get a list of LinkedIn profiles still working in the target company from their domain. This will automatically look them up.

```bash
$ oneaudit socosint linkedin scrap -d example.com -o osint.json
```

```json
{
  "version": 1.1,
  "entries": [
    {
      "source": "rocketreach",
      "date": 1732044168.2800202,
      "version": 1.0,
      "targets": [
        {
          "full_name": "Firstname Lastname",
          "linkedin_url": "https://www.linkedin.com/in/john_doe",
          "birth_year": null,
          "count": 1
        }
      ]
    }
  ]
}
```

After exporting the emails (must be done manually, exporting results using the API is not planned for now), you can prepare them for use with other module with:

```bash
$ # Only keep employees working at LinkedIn
$ oneaudit socosint linkedin parse socosint linkedin parse  -f "LinkedIn" -s rocketreach -i rocketreach_export.json -o contacts.json
```

```json
{
  "version": 1.0,
  "entries": [
    {
      "source": "rocketreach",
      "date": 1732044168.2800202,
      "version": 1.2,
      "targets": [
        {
          "first_name": "John",
          "last_name": "Doe",
          "linkedin_url": "https://www.linkedin.com/in/johndoe",
          "emails": [
            {
              "email": "johndoe@example.com",
              "verified": false
            }
          ]
        }
      ]
    }
  ]
}
```

## Leaks

#### Generate A List Of Targets

We can compute a list of targets from OSINT results.

```bash
$ oneaudit leaks parse -i osint.json -i contacts.json -f flast -d example.com -o targets.json
```

```json
{
  "version": "1.0",
  "credentials": [
    {
      "login": "johndoe@example.com",
      "emails": [
        "johndoe@example.com",
        "johndoe@dev.example.com"
      ]
    }
  ]
}
```

#### Download Leaks For Each Target

You can download leaks and dark web data using the following module.

```bash
$ oneaudit leaks download -i targets.json -o leaks.json --config config.json -d example.com -v
```

```json
{
  "version": 1.3,
  "credentials": [
    {
      "login": "john.doe@example.com",
      "logins": [
        "john.doe",
        "johndoe@example.com",
        "johndoe@dev.example.com",
        "johndoe001"
      ],
      "passwords": [
        "hello"
      ],
      "censored_logins": [
        "jo*******1"
      ],
      "censored_passwords": [
        "h***o"
      ],
      "info_stealers": [],
      "breaches": [
        {
          "name": "Rockyou",
          "source": "2009-01"
        }
      ],
      "hashes": [
        "8d016244527e4d86737d6a3332da6d82"
      ]
    }
  ],
  "additional": {
    "censored_data": [],
    "leaked_urls": []
  }
}
```

## API Configuration

Create a JSON file called `config.json` or specify any file using `--config`. You can also define `--cache` to use an arbitrary folder for cached results.

```bash
$ oneaudit [...] --config config.json --cache .cache
```

The expected format is:

```json
{
  // This API is free, just leave the key empty
  "aura": "",
  "hudsonrocks": "",
  "leakcheck": "",
  "nth": "",
  "spycloud": "",
  // This API is paid, an API key is required
  "hashmob": "your_api_key",
  "rocketreach": "your_api_key",
  "leakcheck_pro": "your_api_key",
  // This API is disabled (leading underscore)
  "_whiteintel": "your_api_key",
}
```

The followed APIs are used by the plugin:

| API Identifier                                     | Pricing    | Usage                                          |
|----------------------------------------------------|------------|------------------------------------------------|
| [rocketreach](https://rocketreach.co/)             | `FREEMIUM` | Access LinkedIn API. Lookup for emails/phones. |
| [hudsonrocks](https://www.hudsonrock.com/cavalier) | `FREE`     | InfoStealer API (censored).                    |
| [whiteintel](https://whiteintel.io/)               | `FREEMIUM` | InfoStealer API (censored).                    |
| [leakcheck](https://leakcheck.io/)                 | `FREE`     | Data breaches API.                             |
| [spycloud](https://spycloud.com/)                  | `FREE`     | Data breaches API.                             |
| [leakcheck_pro](https://leakcheck.io/)             | `PAID`     | Leaked Credentials API.                        |
| [aura](https://scan.aura.com/)                     | `FREE`     | Leaked Credentials API (censored).             |
| [nth](https://github.com/HashPals/Name-That-Hash)  | `FREE`     | Hash Identifier.                               |
| [hashmob](https://hashmob.net/)                    | `FREEMIUM` | Hash Rainbow tables.                           |

Candidates:

* [hashes.com](https://hashes.com/en/docs): hash identifier (FREE) or Rainbow table (PAID)
