from oneaudit.api.leaks import deserialize_result
from oneaudit.utils.logs import args_verbose_config, args_parse_parse_verbose
from json import load as json_load
from jinja2 import Template


def define_args(parent_parser):
    report = parent_parser.add_parser('report', help='Convert passwords to the given hash format')
    report.add_argument('-i', metavar='input.json', dest='input_file', help='JSON file with leaked credentials.', required=True)
    report.add_argument('-f', metavar='format', dest='hash_format', choices=['html'], help='Select a hash format.', required=True)
    report.add_argument('-o', metavar='report.html', dest='output_file', help='File to export results to.', required=True)
    report.add_argument('--all', dest='include_all', action='store_true', help='Include employees that do not have a cleartext password.')
    args_verbose_config(report)


def run(args):
    args_parse_parse_verbose(args)

    html_template = """<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>OneAudit Leaks Report</title>
    <style>
        body {
            font-family: Arial, sans-serif;
            margin: 20px;
            padding: 20px;
        }
        table {
            width: 100%;
            border-collapse: collapse;
        }
        th, td {
            padding: 12px;
            border: 1px solid #ddd;
            text-align: left;
        }
        th {
            background-color: #f4f4f4;
        }
        .green { background-color: #28a745; color: white; }
        .red { background-color: #dc3545; color: white; }
        .breaches, .info-stealers {
            list-style-type: none;
            padding-left: 0;
        }
        .breaches li, .info-stealers li {
            margin: 5px 0;
        }
    </style>
</head>
<body>
    <h1>OneAudit Leaks Report</h1>
    {% if not include_all %}
        <p><b>Warning</b>: No '--all' option provided. Some entries were removed because they don't have a cleartext password.</p>
    {% endif %}
    <table>
        <thead>
            <tr>
                <th>Login</th>
                <th>Passwords</th>
                <th>Hashes</th>
                <th>Verified</th>
                <th>Employed</th>
                <th>Breaches</th>
                <th>Info Stealers</th>
            </tr>
        </thead>
        <tbody>
            {% for user in users %}
            {% if include_all or user['passwords'] %}
            <tr>
                <td>{{ user['login'] }}</td>
                <td>
                    {% for password in user['passwords'] %}
                    {{ password }}<br>
                    {% endfor %}
                </td>
                <td>
                    {% for hash in user['hashes'] %}
                    Uncracked hash found (format={{ hash.format if hash.format else '?' }})<br>
                    {% endfor %}
                </td>
                <td class="{{ 'green' if user['verified'] else 'red' }}">{{ 'True' if user['verified'] else 'False' }}</td>
                <td class="{{ 'green' if user['employed'] else 'red' }}">{{ 'True' if user['employed'] else 'False' }}</td>
                <td>
                    <ul class="breaches">
                        {% for breach in user['breaches'] %}
                        <li>{{ breach }}</li>
                        {% endfor %}
                    </ul>
                </td>
                <td>
                    <ul class="info-stealers">
                        {% for stealer in user['info_stealers'] %}
                        <li>{{ stealer['operating_system'] }} / {{ stealer['date_compromised'] }}</li>
                        {% endfor %}
                    </ul>
                </td>
            </tr>
            {% endif %}
            {% endfor %}
        </tbody>
    </table>
</body>
</html>
"""
    with open(args.input_file, 'r', encoding='utf-8') as input_file:
        data = json_load(input_file)

    template = Template(html_template)
    html_output = template.render(include_all=args.include_all, users=[deserialize_result(cred) for cred in data['credentials']])
    with open(args.output_file, 'w') as file:
        file.write(html_output)
