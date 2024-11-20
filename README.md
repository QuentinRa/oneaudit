<div align="center">

![LOGO](.github/dalle_logo.png)

[![GitHub](https://img.shields.io/github/license/QuentinRa/oneaudit)](LICENSE)
[![GitHub issues closed](https://img.shields.io/github/issues-closed/QuentinRa/oneaudit?color=%23a0)](https://github.com/QuentinRa/oneaudit/issues)
[![GitHub pull requests closed](https://img.shields.io/github/issues-pr-closed/QuentinRa/oneaudit?color=%23a0)](https://github.com/QuentinRa/oneaudit/pulls)
[![GitHub commit activity](https://img.shields.io/github/commit-activity/m/QuentinRa/oneaudit)](https://github.com/QuentinRa/oneaudit)
</div>

WIP

* Use given cache folder or temporary as default
* Support wildcard import for LinkedIn Parser
* Can generate a company email during "parsing"

```json!
{
    "version": 1.0,
    "credentials": [
        {
            "login": "user1@example.com",
            "passwords": ["pass1", "pass2"]
        }
    ]
}
```

## SocOSINT

### LinkedIn OSINT

✍️ Get name, birthdate, and other PII. Additionally, can lookup for emails.

You can use this module to get a list of LinkedIn profiles still working in the target company from their domain. This will automatically look them up.

```bash
$ oneaudit socosint linkedin -d example.com -o results/linkedin.json
```

```json
{
  "version": 1.0,
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
          "_status": "complete",
          "_count": 1
        }
      ]
    }
  ]
}
```

After exporting the results (must be done manually), you can prepare them for use with the **leaks** module with:

```bash
$ oneaudit socosint linkedin parse -f "rocketreach" -i rocketreach_export.json -o linkedin_contacts.json
```

```json
{
  "version": 1.0,
  "entries": [
    {
      "first_name": "John",
      "last_name": "Doe",
      "linkedin_url": "https://www.linkedin.com/in/johndoe",
      "emails": [
        "johndoe@example.com"
      ]
    }
  ]
}
```

## API Configuration

Create a JSON file called `config.json` or specify any file using `--config`. The expected format is:

```json
{
  "api_identifier": "your_api_key"
}
```

The followed APIs are used by the plugin:

| API Identifier                         | Pricing    | Usage                                          |
|----------------------------------------|------------|------------------------------------------------|
| [rocketreach](https://rocketreach.co/) | `FREEMIUM` | Access LinkedIn API. Lookup for emails/phones. |
|                                        |            |                                                |
