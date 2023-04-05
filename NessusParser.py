import csv
from collections import OrderedDict
import xlsxwriter
import sys

if len(sys.argv) < 3:
    print('Missing arguments:\n\t{} [input_file.csv] [output_file.xlsx]'.format(sys.argv[0]))
    sys.exit()

networks_hosts_count = {}
ports_protocols = {}
high_critical_ports_protocols = {}
high_critical_detailed = {}
all_hosts = set()
misconfigured_count = 0
outdated_count = 0

cols_replacements = (('0', 'A'), ('1', 'B'), ('2', 'C'), ('3', 'D'), ('4', 'E'), ('5', 'F'), ('6', 'G'))


def col_replace(column):
    for old, new in cols_replacements:
        column = str(column).replace(old, new)
    return column


with open(sys.argv[1]) as csv_file:
    csv_reader = csv.DictReader(csv_file, delimiter=',')
    counter = 0
    for row in csv_reader:
        if counter > 0:
            name = row['Name']
            host = row['Host']
            risk = row['Risk']
            port = row['Port']
            solution = row['Solution']
            protocol = row['Protocol']
            network = '.'.join(host.split('.')[:-1])
            if network not in networks_hosts_count:
                networks_hosts_count[network] = {'None': 0, 'Low': 0, 'Medium': 0, 'High': 0, 'Critical': 0, 'Hosts': 0}
            if host not in all_hosts:
                all_hosts.add(host)
                networks_hosts_count[network]['Hosts'] += 1
            networks_hosts_count[network][risk] += 1
            if risk != 'None':
                if port != '0':
                    if port not in ports_protocols:
                        ports_protocols[port] = {}
                        ports_protocols[port][protocol] = 1
                    elif protocol not in ports_protocols[port]:
                        ports_protocols[port][protocol] = 1
                    else:
                        ports_protocols[port][protocol] += 1
                if risk == 'Critical' or risk == 'High':
                    if port != 0:
                        if port not in high_critical_ports_protocols:
                            high_critical_ports_protocols[port] = {}
                            high_critical_ports_protocols[port][protocol] = 1
                        elif protocol not in high_critical_ports_protocols[port]:
                            high_critical_ports_protocols[port][protocol] = 1
                        else:
                            high_critical_ports_protocols[port][protocol] += 1
                        if name not in high_critical_detailed:
                            high_critical_detailed[name] = {}
                            high_critical_detailed[name]['counter'] = 1
                            high_critical_detailed[name]['hosts'] = set()
                            high_critical_detailed[name]['hosts'].add(host)
                            high_critical_detailed[name]['solution'] = solution
                        else:
                            high_critical_detailed[name]['counter'] += 1
                            high_critical_detailed[name]['hosts'].add(host)
                if 'update' in solution or 'Update' in solution or 'upgrade' in solution or 'Upgrade' in solution:
                    outdated_count += 1
                else:
                    misconfigured_count += 1
        counter += 1

total_vulns = networks_hosts_count[network]['Low'] + networks_hosts_count[network]['Medium'] + \
              networks_hosts_count[network]['High'] + networks_hosts_count[network]['Critical']

# xlsx file output
row = 0
col = 0

workbook = xlsxwriter.Workbook(sys.argv[2])
worksheet = workbook.add_worksheet()
centered = workbook.add_format({'align': 'center'})
red_centered = workbook.add_format({'font_color': 'red', 'align': 'center'})
green = workbook.add_format({'font_color': 'green'})
bold = workbook.add_format({'bold': True})
bold_centered = workbook.add_format({'bold': True, 'locked': True, 'align': 'center'})

worksheet.write(row, col, 'Hosts')
col += 1
worksheet.write(row, col, len(all_hosts), centered)
col += 2
worksheet.write(row, col, 'Networks')
col += 1
worksheet.write(row, col, len(networks_hosts_count), centered)

for network in networks_hosts_count:
    col = 0
    row += 2
    worksheet.write(row, col, 'Network')
    col += 1
    worksheet.write(row, col, network, centered)
    col += 2
    worksheet.write(row, col, 'Hosts')
    col += 1
    worksheet.write(row, col, networks_hosts_count[network]['Hosts'], centered)
    col -= 1
    row += 2
    worksheet.write(row, col, 'Info')
    col += 1
    worksheet.write(row, col, networks_hosts_count[network]['None'], centered)
    col = 1
    worksheet.write(row, col, 'Low')
    col += 1
    worksheet.write(row, col, networks_hosts_count[network]['Low'], centered)
    col = 1
    row += 1
    worksheet.write(row, col, 'Medium')
    col += 1
    worksheet.write(row, col, networks_hosts_count[network]['Medium'], centered)
    col = 1
    row += 1
    worksheet.write(row, col, 'High')
    col += 1
    worksheet.write(row, col, networks_hosts_count[network]['High'], red_centered)
    col = 1
    row += 1
    worksheet.write(row, col, 'Critical')
    col += 1
    worksheet.write(row, col, networks_hosts_count[network]['Critical'], red_centered)
    col = 1
    row += 1
    worksheet.write(row, col, 'Total', bold)
    col += 1
    worksheet.write_formula(row, col, '=SUM({}{}:{}{})'.format(col_replace(col), row - 3, col_replace(col), row),
                            bold_centered, total_vulns)

row += 3
col = 0

worksheet.write(row, col, 'Vulnerabilities by port')
row += 2
col += 1
worksheet.write(row, col, 'Port', centered)
col += 1
worksheet.write(row, col, 'Protocol', centered)
col += 1
worksheet.write(row, col, 'Total', bold_centered)
for port in ports_protocols:
    for protocol in ports_protocols[port]:
        row += 1
        col = 1
        worksheet.write(row, col, port, centered)
        col += 1
        worksheet.write(row, col, protocol, centered)
        col += 1
        worksheet.write(row, col, ports_protocols[port][protocol], bold_centered)

row += 3
col = 0

worksheet.write(row, col, 'Critical / High vulnerabilities by port')
row += 2
col += 1
worksheet.write(row, col, 'Port', centered)
col += 1
worksheet.write(row, col, 'Protocol', centered)
col += 1
worksheet.write(row, col, 'Total', bold_centered)
for port in high_critical_ports_protocols:
    for protocol in high_critical_ports_protocols[port]:
        row += 1
        col = 1
        worksheet.write(row, col, port, centered)
        col += 1
        worksheet.write(row, col, protocol, centered)
        col += 1
        worksheet.write(row, col, high_critical_ports_protocols[port][protocol], bold_centered)

row += 3
col = 0

worksheet.write(row, col, 'Critical / High vulnerabilities detailed')
for name in high_critical_detailed:
    row += 2
    col = 1
    worksheet.write(row, col, 'Vuln')
    col += 1
    worksheet.write(row, col, name, red_centered)
    row += 1
    col = 1
    worksheet.write(row, col, 'Number of affected hosts')
    col += 1
    worksheet.write(row, col, high_critical_detailed[name]['counter'], centered)
    row += 1
    col = 1
    worksheet.write(row, col, 'Affected hosts addresses')
    col += 1
    hosts = ''
    for host in high_critical_detailed[name]['hosts']:
        hosts += '{}; '.format(host)
    worksheet.write(row, col, hosts, centered)
    row += 1
    col = 1
    worksheet.write(row, col, 'Solution')
    col += 1
    solution = high_critical_detailed[name]['solution'].split()
    solution = ' '.join(solution)
    worksheet.write(row, col, solution, green)

row += 3
col = 0

other_causes_count = total_vulns - misconfigured_count - outdated_count
worksheet.write(row, col, 'Following data is not accurate!!!')
row += 2
col = 1
worksheet.write(row, col, 'Misconfigurations')
col += 1
worksheet.write(row, col, misconfigured_count, centered)
col = 1
row += 1
worksheet.write(row, col, 'Outdated software')
col += 1
worksheet.write(row, col, outdated_count, centered)
col = 1
row += 1
worksheet.write(row, col, 'Other causes')
col += 1
worksheet.write(row, col, other_causes_count, centered)

workbook.close()

# console output

if len(networks_hosts_count) < 2:
    print('\n\nScanned {} hosts in {} network'.format(len(all_hosts), len(networks_hosts_count)))
else:
    print('\n\nScanned {} hosts in {} networks'.format(len(all_hosts), len(networks_hosts_count)))

for network in networks_hosts_count:
    total_vulns = 0
    for x in networks_hosts_count[network]:
        if x != 'None' and x != 'Hosts':
            total_vulns += networks_hosts_count[network][x]
    print('\n\nNetwork {}.X\t\tHosts:\t{}\t\tInfo:\t{}'.format(network, networks_hosts_count[network]['Hosts'],
                                                               networks_hosts_count[network]['None']))
    print('\n\tLow:\t\t{}\n\tMedium:\t\t{}\n\tHigh:\t\t{}\n\tCritical:\t{}\n\tTotal:\t\t{}'.format(
        networks_hosts_count[network]['Low'], networks_hosts_count[network]['Medium'],
        networks_hosts_count[network]['High'], networks_hosts_count[network]['Critical'], total_vulns))

print('\n\nVulnerabilities by port:\n')
ports_protocols = OrderedDict(sorted(ports_protocols.items(), key=lambda y: int(y[0])))
for port in ports_protocols:
    for protocol in ports_protocols[port]:
        print('\t{}\t{}  \t\t--> {}'.format(port, protocol, ports_protocols[port][protocol]))

print('\n\nCritical / High vulnerabilities by port:\n')
high_critical_ports_protocols = OrderedDict(sorted(high_critical_ports_protocols.items(), key=lambda y: int(y[0])))
for port in high_critical_ports_protocols:
    for protocol in high_critical_ports_protocols[port]:
        print('\t{} {}  \t\t--> {}'.format(port, protocol, high_critical_ports_protocols[port][protocol]))

print('\n\nCritical / High vulnerabilities detailed:\n')
for name in high_critical_detailed:
    print('\tVuln:\t\t\t\t\t\t{}'.format(name))
    print('\tNumber of affected hosts:\t{}'.format(high_critical_detailed[name]['counter']))
    hosts = ''
    for host in high_critical_detailed[name]['hosts']:
        hosts += '{}; '.format(host)
    print('\tAffected hosts addresses:\t{}'.format(hosts))
    solution = high_critical_detailed[name]['solution'].split()
    solution = ' '.join(solution)
    print('\tSolution:\t\t\t\t\t{}'.format(solution))

print('\n\n\nFollowing data is not accurate!!!')
print('\n\tMisconfigurations:\t{}\n\tOutdated software:\t{}\n\tOther causes:\t{}'.format(
    misconfigured_count, outdated_count, other_causes_count))
