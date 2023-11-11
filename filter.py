import re
import ipaddress

def read_log_file():
    while True:
        file_path = input("Enter the path to the log file (e.g., /path/to/logfile.log) or type 'exit' to quit: ")
        if file_path.lower() == 'exit':
            return None
        elif file_path.lower().endswith('.log'):
            try:
                with open(file_path, 'r') as file:
                    log_data = file.read()
                return log_data
            except FileNotFoundError:
                print(f"File not found at {file_path}. Please enter a valid file path.")
        else:
            print("Invalid file format. Please enter a valid .log file.")

def process_log_data(log_data):
    # Find the index '# Fields:'
    fields_index = log_data.find('# Fields:')

    # Find the index '# End of log'
    end_index = log_data.find('# End of log')

    # Extract the data rows 
    data_section = log_data[fields_index + len('# Fields:'):end_index].strip()

    # Remove the "Info" column from the header
    header = [col.strip() for col in data_section.split('|')[:-1]]
    tcp_flags_index = header.index('TCP Flags') if 'TCP Flags' in header else None

    # Process the data rows
    data_rows = []
    for row in data_section.split('\n')[1:]:
        # Split the row by any amount of whitespace and remove empty elements
        columns = [col.strip() for col in re.split(r'\s+', row.strip())]

        # Join "Info" column
        if tcp_flags_index is not None and len(columns) > tcp_flags_index + 1:
            columns[tcp_flags_index + 1] = " ".join(columns[tcp_flags_index + 1:])

        # Remove the remaining columns 
        if tcp_flags_index is not None:
            columns = columns[:tcp_flags_index + 2]

        # Add the row to the data_rows list
        data_rows.append(columns)

    return header, data_rows

def filter_ssh_unusual_attempts(header, data_rows):
    # Filter data SSH Unusual Attempts 
    ssh_unusual_attempts_table = [row for row in data_rows if row[header.index('Dst Port')] == '22' and not row[header.index('Dst IP')].startswith('192.168')]
    return ssh_unusual_attempts_table

def filter_sql_unusual_access(header, data_rows):
    # Filter data SQL Unusual Access
    sql_unusual_access_table = [row for row in data_rows if row[header.index('Dst Port')] == '1433' and not row[header.index('Dst IP')].startswith('192.168')]
    return sql_unusual_access_table

def filter_port_80_attempts(header, data_rows):
    # Filter data Port 80 
    port_80_attempts_table = [row for row in data_rows if row[header.index('Dst Port')] == '80' and not row[header.index('Dst IP')].startswith('192.168')]
    return port_80_attempts_table

def filter_allowed_connections(header, data_rows):
    # Filter data Allowed Connections 
    allowed_connections_table = [row for row in data_rows if row[header.index('Action')] == 'ALLOW']
    return allowed_connections_table

def filter_blocked_connections(header, data_rows):
    # Filter data Blocked Connections 
    blocked_connections_table = [row for row in data_rows if row[header.index('Action')] == 'BLOCK']
    return blocked_connections_table

def filter_tcp_connections(header, data_rows):
    # Filter data TCP Connections 
    tcp_connections_table = [row for row in data_rows if row[header.index('Protocol')] == 'TCP']
    return tcp_connections_table

def filter_udp_connections(header, data_rows):
    # Filter data UDP Connections 
    udp_connections_table = [row for row in data_rows if row[header.index('Protocol')] == 'UDP']
    return udp_connections_table

def filter_public_connection_attempts(header, data_rows):
    # Filter Public Connection Attempts 
    private_ip_ranges = [ipaddress.IPv4Network('10.0.0.0/8'), ipaddress.IPv4Network('172.16.0.0/12'), ipaddress.IPv4Network('192.168.0.0/16')]
    public_connection_attempts_table = [row for row in data_rows if not ipaddress.IPv4Address(row[header.index('Dst IP')]) in private_ip_ranges]
    return public_connection_attempts_table

def display_table(title, header, data_rows):
    # Print title
    print(f"\n{title}")

    # Print header
    print("| " + " | ".join(header) + " |")

    # Print rows
    for row in data_rows:
        print("| " + " | ".join(row) + " |")

def main():
    while True:
        log_data = read_log_file()

        if log_data is None:
            print("Exiting the script.")
            break

        header, data_rows = process_log_data(log_data)

        if not data_rows:
            print("No data found in the log file.")
        else:
            # Display the main table
            display_table("Main Table", header, data_rows)

            #  SSH Unusual Attempts
            ssh_unusual_attempts_table = filter_ssh_unusual_attempts(header, data_rows)
            display_table("SSH Unusual Attempts", header, ssh_unusual_attempts_table)

            #  SQL Unusual Access
            sql_unusual_access_table = filter_sql_unusual_access(header, data_rows)
            display_table("SQL Unusual Access", header, sql_unusual_access_table)

            #  Port 80 (HTTP) attempts
            port_80_attempts_table = filter_port_80_attempts(header, data_rows)
            display_table("Port 80 (HTTP) attempts", header, port_80_attempts_table)

            #  Allowed Connections
            allowed_connections_table = filter_allowed_connections(header, data_rows)
            display_table("Allowed Connections", header, allowed_connections_table)

            # Blocked Connections
            blocked_connections_table = filter_blocked_connections(header, data_rows)
            display_table("Blocked Connections", header, blocked_connections_table)

            #  TCP Connections
            tcp_connections_table = filter_tcp_connections(header, data_rows)
            display_table("TCP Connections", header, tcp_connections_table)

            #  UDP Connections
            udp_connections_table = filter_udp_connections(header, data_rows)
            display_table("UDP Connections", header, udp_connections_table)

            #  Public Connection Attempts
            public_connection_attempts_table = filter_public_connection_attempts(header, data_rows)
            display_table("Public Connection Attempts", header, public_connection_attempts_table)

            # to exit
            user_input = input("Type 'exit' to quit or press Enter to continue: ")
            if user_input.lower() == 'exit':
                print("Exiting the script.")
                break

if __name__ == "__main__":
    main()

    # keep the console window 
    input("Press Enter to exit.")
