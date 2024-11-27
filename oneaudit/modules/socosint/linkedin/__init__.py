import oneaudit.modules.socosint.linkedin.scrap
import oneaudit.modules.socosint.linkedin.export
import oneaudit.modules.socosint.linkedin.parse

def define_args(parent_parser):
    linkedin_module = parent_parser.add_parser('linkedin')

    # Add actions we can perform against this platform
    linkedin_module_action = linkedin_module.add_subparsers(dest='action', help="Action to perform.", required=True)
    oneaudit.modules.socosint.linkedin.scrap.define_args(linkedin_module_action)
    oneaudit.modules.socosint.linkedin.export.define_args(linkedin_module_action)
    oneaudit.modules.socosint.linkedin.parse.define_args(linkedin_module_action)