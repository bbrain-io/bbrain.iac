import click
from bbrain.iac.ovh.cli import ovh


@click.group()
def cli():
    pass


cli.add_command(ovh)
