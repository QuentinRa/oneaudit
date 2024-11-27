import oneaudit.modules.socosint.linkedin

def define_args(parent_parser):
    socosint_module = parent_parser.add_parser('socosint', help='Social Networks OSINT')

    # Add Social Networks
    submodule_parser = socosint_module.add_subparsers(dest='scope', help="Target Social Networks", required=True)
    linkedin.define_args(submodule_parser)