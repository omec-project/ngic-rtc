import click
import requests
from collections import OrderedDict
import json
import copy

HEADER = {"X-User-Name": "test", "Content-Type": "application/json"}
CONTEXT_SETTINGS = dict(help_option_names=['-h', '--help'])

@click.group(context_settings=CONTEXT_SETTINGS)
@click.argument('c3po_url')
@click.pass_context
def c3pocli(ctx, c3po_url):
    """This script connects to the c3po endpoint C3PO_URL and issues rest commands against it"""
    ctx.obj = {}
    ctx.obj['C3PO_URL'] = c3po_url
    pass

@click.group()
@click.pass_context
def admin(ctx):
    pass

@click.group()
@click.pass_context
def stats(ctx):
    pass

@click.group()
@click.pass_context
def logger(ctx):
    pass

@click.group()
@click.pass_context
def config(ctx):
    pass

@click.group()
@click.pass_context
def pcap(ctx):
    pass

@click.command()
@click.pass_context
def describe_stats_frequency(ctx):
    url = ctx.obj['C3PO_URL'] + "/statfreq"
    r = requests.get(url, headers=HEADER)
    click.echo(r.json())

@click.command()
@click.pass_context
@click.option('--freq', '-f', required=True, type=int, help='Stats generation interval in millisecond')
def set_stats_frequency(ctx, freq):
    url = ctx.obj['C3PO_URL'] + "/statfreq"
    r = requests.post(url, json={"statfreq": freq}, headers=HEADER)
    click.echo(r.json())

@click.command()
@click.pass_context
def describe_stats_live(ctx):
    url = ctx.obj['C3PO_URL'] + "/statlive"
    r = requests.get(url, headers=HEADER)
    res = r.json()
    new_res = copy.deepcopy(res)
    click.echo(json.dumps(res))

@click.command()
@click.pass_context
def describe_stats_all(ctx):
    url = ctx.obj['C3PO_URL'] + "/statliveall"
    r = requests.get(url, headers=HEADER)
    res = r.json()
    new_res = copy.deepcopy(res)
    click.echo(json.dumps(res))

@click.command()
@click.pass_context
def describe_loggers(ctx):
    url = ctx.obj['C3PO_URL'] + "/logger"
    r = requests.get(url, headers=HEADER)
    click.echo(r.json())

@click.command()
@click.pass_context
def describe_stats_logging(ctx):
    url = ctx.obj['C3PO_URL'] + "/statlogging"
    r = requests.get(url, headers=HEADER)
    click.echo(r.json())

@click.command()
@click.pass_context
@click.option('--name', '-n', required=True, help='Enter stat logging name suppress or all')
def set_stats_logging(ctx, name):
    url = ctx.obj['C3PO_URL'] + "/statlogging"
    r = requests.post(url, json={"statlog": name }, headers=HEADER)
    click.echo(r.json())

@click.command()
@click.pass_context
@click.option('--name', '-n', required=True, help='Logger name')
@click.option('--level', '-l', required=True, type=int, help='Logger level')
def set_logger_level(ctx, name, level):
    url = ctx.obj['C3PO_URL'] + "/logger"
    r = requests.post(url, json={"name": name, "level": level}, headers=HEADER)
    click.echo(json.dumps(r.json()))


@click.command()
@click.pass_context
def describe_oss_options(ctx):
    url = ctx.obj['C3PO_URL'] + "/ossoptions"
    r = requests.get(url, headers=HEADER)
    click.echo(r.json())

@click.command()
@click.pass_context
def describe_transmit_count(ctx):
    url = ctx.obj['C3PO_URL'] + "/transmit_count"
    r = requests.get(url, headers=HEADER)
    click.echo(json.dumps(r.json()))

@click.command()
@click.pass_context
@click.option('--transmit', '-t', required=True, type=int, help='set transmit count')
def set_transmit_count(ctx,transmit):
    url = ctx.obj['C3PO_URL'] + "/transmit_count"
    res = requests.post(url, json={"transmit_count": transmit}, headers=HEADER)
    click.echo(json.dumps(res.json()))

@click.command()
@click.pass_context
def describe_request_tries(ctx):
    url = ctx.obj['C3PO_URL'] + "/request_tries"
    r = requests.get(url, headers=HEADER)
    click.echo(json.dumps(r.json()))

@click.command()
@click.pass_context
@click.option('--request_tries', '-r', required=True, type=int, help='set request tries')
def set_request_tries(ctx,request_tries):
    url = ctx.obj['C3PO_URL'] + "/request_tries"
    res = requests.post(url, json={"request_tries": request_tries}, headers=HEADER)
    click.echo(json.dumps(res.json()))

@click.command()
@click.pass_context
def describe_request_timeout(ctx):
    url = ctx.obj['C3PO_URL'] + "/request_timeout"
    r = requests.get(url, headers=HEADER)
    click.echo(json.dumps(r.json()))

@click.command()
@click.pass_context
@click.option('--request_timeout', '-r', required=True, type=int, help='set request timeout')
def set_request_timeout(ctx,request_timeout):
    url = ctx.obj['C3PO_URL'] + "/request_timeout"
    res = requests.post(url, json={"request_timeout": request_timeout}, headers=HEADER)
    click.echo(json.dumps(res.json()))

@click.command()
@click.pass_context
@click.option('--reset', '-r', required=False, type=int, help='reset stats count')
def set_stats_reset(ctx,reset):
    url = ctx.obj['C3PO_URL'] + "/reset_stats"
    res = requests.post(url, json={"reset_stats":reset}, headers=HEADER)
    click.echo(json.dumps(res.json()))


@click.command()
@click.pass_context
def describe_transmit_timer(ctx):
    url = ctx.obj['C3PO_URL'] + "/transmit_timer"
    r = requests.get(url, headers=HEADER)
    click.echo(json.dumps(r.json()))

@click.command()
@click.pass_context
@click.option('--transmit_timer', '-t', required=True, type=int, help='set transmit timer')
def set_transmit_timer(ctx,transmit_timer):
    url = ctx.obj['C3PO_URL'] + "/transmit_timer"
    res = requests.post(url, json={"transmit_timer": transmit_timer}, headers=HEADER)
    click.echo(json.dumps(res.json()))

@click.command()
@click.pass_context
@click.option('--perf_flag', '-pf', required=True, type=int, help='set perf flag')
def set_perf_flag(ctx,perf_flag):
    url = ctx.obj['C3PO_URL'] + "/perf_flag"
    res = requests.post(url, json={"perf_flag": perf_flag}, headers=HEADER)
    click.echo(json.dumps(res.json()))

@click.command()
@click.pass_context
def describe_periodic_timer(ctx):
    url = ctx.obj['C3PO_URL'] + "/periodic_timer"
    r = requests.get(url, headers=HEADER)
    click.echo(json.dumps(r.json()))

@click.command()
@click.pass_context
def describe_perf_flag(ctx):
    url = ctx.obj['C3PO_URL'] + "/perf_flag"
    r = requests.get(url, headers=HEADER)
    click.echo(json.dumps(r.json()))

@click.command()
@click.pass_context
@click.option('--periodic_timer', '-p', required=True, type=int, help='set periodic timer')
def set_periodic_timer(ctx,periodic_timer):
    url = ctx.obj['C3PO_URL'] + "/periodic_timer"
    res = requests.post(url, json={"periodic_timer": periodic_timer}, headers=HEADER)
    click.echo(json.dumps(res.json()))

@click.command()
@click.pass_context
def describe_config_live(ctx):
    url = ctx.obj['C3PO_URL'] + "/configlive"
    r = requests.get(url, headers=HEADER)
    click.echo(json.dumps(r.json()))

@click.command()
@click.pass_context
def describe_pcap_generation_status(ctx):
	url = ctx.obj['C3PO_URL'] + "/generate_pcap"
	r = requests.get(url, headers=HEADER)
	click.echo(json.dumps(r.json()))

@click.command()
@click.pass_context
@click.option('--generate_pcap', '-g', required=True, help='set pcap generation command')
def set_pcap_generation(ctx, generate_pcap):
    url = ctx.obj['C3PO_URL'] + "/generate_pcap"
    res = requests.post(url, json={"generate_pcap": generate_pcap}, headers=HEADER)
    click.echo(json.dumps(res.json()))

c3pocli.add_command(admin)
c3pocli.add_command(stats)
c3pocli.add_command(logger)
c3pocli.add_command(config)
c3pocli.add_command(pcap)

admin.add_command(describe_oss_options)

stats.add_command(describe_stats_frequency)
stats.add_command(set_stats_frequency)
stats.add_command(describe_stats_live)
stats.add_command(describe_stats_all)
stats.add_command(describe_stats_logging)
stats.add_command(set_stats_logging)
stats.add_command(set_stats_reset)

config.add_command(describe_transmit_count)
config.add_command(set_transmit_count)
config.add_command(describe_request_tries)
config.add_command(set_request_tries)
config.add_command(describe_request_timeout)
config.add_command(set_request_timeout)
config.add_command(describe_transmit_timer)
config.add_command(set_transmit_timer)
config.add_command(describe_periodic_timer)
config.add_command(set_periodic_timer)
config.add_command(describe_config_live)
config.add_command(describe_perf_flag)
config.add_command(set_perf_flag)

logger.add_command(describe_loggers)
logger.add_command(set_logger_level)

pcap.add_command(describe_pcap_generation_status)
pcap.add_command(set_pcap_generation)
