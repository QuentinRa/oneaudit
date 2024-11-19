<div align="center">

![LOGO](.github/dalle_logo.png)

[![GitHub](https://img.shields.io/github/license/QuentinRa/oneaudit)](LICENSE)
[![GitHub issues closed](https://img.shields.io/github/issues-closed/QuentinRa/oneaudit?color=%23a0)](https://github.com/QuentinRa/oneaudit/issues)
[![GitHub pull requests closed](https://img.shields.io/github/issues-pr-closed/QuentinRa/oneaudit?color=%23a0)](https://github.com/QuentinRa/oneaudit/pulls)
[![GitHub commit activity](https://img.shields.io/github/commit-activity/m/QuentinRa/oneaudit)](https://github.com/QuentinRa/oneaudit)
</div>

WIP

* Use given cache folder or temporary as default
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

You can use this module to get a list of LinkedIn profiles still working in the target company from their domain.

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

After exporting the results (e.g., as JSON using webhooks for RocketReach), you can parse them with:

```bash
$ oneaudit socosint linkedin parse -f "rocketreach" -i rocketreach_export.json -o linkedin_emails.json
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
