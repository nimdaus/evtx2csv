from evtx import PyEvtxParser
import json
import csv
import os
from datetime import datetime
import sys

def main():

    input_path = sys.argv[1] #"/Users/x/Documents/evtx2/evtx_dir"
    output_path = sys.argv[2] #"/Users/x/Documents/evtx2/"

    now = datetime.now()
    dt_string = now.strftime("%Y-%m-%d_%H:%M")
    data_file = open(f"{output_path}/EventOutput_{dt_string}.csv", 'w', newline='')
    csv_writer = csv.writer(data_file, delimiter=',', quoting=csv.QUOTE_MINIMAL)

    header = [
        'Detection Time',
        'Rule ID',
        'Rule Name',
        'Event ID',
        'Hostname',
        'Destination',
        'Involved File',
        'Inhertiance Flags',
        'Parent Commandline',
        'Path',
        'Process Name',
        'Process ID',
        'Thread ID',
        'User',
        'User SID'
    ]

    csv_writer.writerow(header)

    for file in os.listdir(input_path):
        if file[-5:] == ".evtx":

            with open(f"{input_path}/{file}", 'rb') as evtx_file:
                evtx_parser = PyEvtxParser(evtx_file)
                for record in evtx_parser.records_json():
                    record_json = json.loads(record['data'])

                    #Event Filter
                    event_id = record_json['Event']['System']['EventID']
                    if event_id == 1121 or event_id == 1122:
                        # print(json.dumps(record_json, indent = 3))

                        #Rule Map
                        Rules = {
                            "56a863a9-875e-4185-98a7-b882c64b5ce5":"Block abuse of exploited vulnerable signed drivers",
                            "7674ba52-37eb-4a4f-a9a1-f0f9a1619a2c":"Block Adobe Reader from creating child processes",
                            "d4f940ab-401b-4efc-aadc-ad5f3c50688a":"Block all Office applications from creating child processes",
                            "9e6c4e1f-7d60-472f-ba1a-a39ef669e4b2":"Block credential stealing from the Windows local security authority subsystem",
                            "be9ba2d9-53ea-4cdc-84e5-9b1eeee46550":"Block executable content from email client and webmail",
                            "01443614-cd74-433a-b99e-2ecdc07bfc25":"Block executable files from running unless they meet a prevalence, age, or trusted list criterion",
                            "5beb7efe-fd9a-4556-801d-275e5ffc04cc":"Block execution of potentially obfuscated scripts",
                            "d3e037e1-3eb8-44c8-a917-57927947596d":"Block JavaScript or VBScript from launching downloaded executable content",
                            "3b576869-a4ec-4529-8536-b80a7769e899":"Block Office applications from creating executable content",
                            "75668c1f-73b5-4cf0-bb93-3ecf5cb7cc84":"Block Office applications from injecting code into other processes",
                            "26190899-1602-49e8-8b27-eb1d0a1ce869":"Block Office communication application from creating child processes",
                            "e6db77e5-3df2-4cf1-b95a-636979351e5b":"Block persistence through WMI event subscription",
                            "d1e49aac-8f56-4280-b9ba-993a6d77406c":"Block process creations originating from PSExec and WMI commands",
                            "b2b3f03d-6a65-4f7b-a9c7-1c7ef74a9ba4":"Block untrusted and unsigned processes that run from USB",
                            "92e97fa1-2edf-4476-bdd6-9dd0b4dddc7b":"Block Win32 API calls from Office macros",
                            "c1db55ab-c21a-4637-bb3f-a12568109d35":"Use advanced protection against ransomware"
                            }

                        for k, v in Rules.items():
                            if record_json['Event']['EventData']['ID'].lower() == k:
                                Rule_Name = v
                            else:
                                Rule_name = None

                        row = [
                            record_json['Event']['EventData']['Detection Time'],
                            record_json['Event']['EventData']['ID'],
                            Rule_Name,
                            record_json['Event']['System']['EventID'],
                            record_json['Event']['System']['Computer'],
                            None,
                            record_json['Event']['EventData']['Involved File'],
                            record_json['Event']['EventData']['Inhertiance Flags'],
                            record_json['Event']['EventData']['Parent Commandline'],
                            record_json['Event']['EventData']['Path'],
                            record_json['Event']['EventData']['Process Name'],
                            record_json['Event']['System']['Execution']['#attributes']['ProcessID'],
                            record_json['Event']['System']['Execution']['#attributes']['ThreadID'],
                            record_json['Event']['EventData']['User'],
                            record_json['Event']['System']['Security']['#attributes']['UserID']
                        ]
                        csv_writer.writerow(row)

                    if event_id == 1125 or event_id == 1126:
                        row = [
                            record_json['Event']['EventData']['Detection Time'],
                            record_json['Event']['EventData']['ID'],
                            "Network Protection",
                            record_json['Event']['System']['EventID'],
                            record_json['Event']['System']['Computer'],
                            record_json['Event']['EventData']['Destination'],
                            None,
                            None,
                            None,
                            None,
                            record_json['Event']['EventData']['Process Name'],
                            record_json['Event']['System']['Execution']['#attributes']['ProcessID'],
                            record_json['Event']['System']['Execution']['#attributes']['ThreadID'],
                            record_json['Event']['EventData']['User'],
                            record_json['Event']['System']['Security']['#attributes']['UserID']
                        ]
                        csv_writer.writerow(row)

                    else:
                        continue

    data_file.close()

if __name__=='__main__':
    main()