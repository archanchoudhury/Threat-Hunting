# Threat Hunting with Splunk- Process Creation Log Analysis

## Overview
In the ransomware hunt series, I introduced you to process creation log sources in Windows, relevant data fields for analysis, and instructions on how to import this data into Splunk. Here I am going to focus on some basic queries you can use to interrogate those logs and how to filter benign results. There will also be a small section on hypothesis and questions you can ask of this data to help discover anomalous activity.

## Queries to Jump Start your Threat Hunting

### Basics
There are a wide variety of possibilities and all sorts of different ways you can manipulate the data depending on what it is you are trying to do. I’m going to show you a couple of introductory searches I put together that might give you some ideas on where to start, and then give you some ideas for manipulating the data in the form of questions you could use process creation logs to answer.

```sourcetype="WinEventLog" EventCode=4688 | stats count by New_Process_Name, Process_Command_Line```

This search queries the “WinEventLog” sourcetype (substitute this with the sourcetype you are dumping your windows event logs to). We’re looking for all EventCode 4688 entries (process creation). From there, we’re piping this query to the stats command, listing out all of the executables that have been seen for a given time period, and sorting them by how many times they have been executed, AND by similar command line arguments.

Below is the similar query if you are using SYSMON log source-

```sourcetype="XmlWinEventLog:Microsoft-Windows-Sysmon/Operational" EventID=1 | stats count by Image, CommandLine```

### Powershell

Just like the Windows Process logs, expect a large number of events back. We’ll get into looking at specific processes and/or filtering in just a moment. Here is an example WinEventLog query, specifically looking for powershell.exe process creation events:

```sourcetype="WinEventLog" EventCode=4688 New_Process_Name="*powershell.exe" | stats count by New_Process_Name, Process_Command_Line```

Here’s something identical for sysmon logs:

```sourcetype="XmlWinEventLog:Microsoft-Windows-Sysmon/Operational" EventID=1 Image="*powershell.exe" | stats count by Image, CommandLine```

As many are already aware, Powershell is a scripting language created by Microsoft, built with system administrators in mind. A lot of newer Microsoft software is built with integration into Powershell. Microsoft wants system administrators to use Powershell for managing and maintaining Windows networks.

So, this query is a good start and all, but what can I do if I run into things I don’t want to see and/or want to filter out? Try this WinEventLog query:

```sourcetype="WinEventLog" EventCode=4688 New_Process_Name="*powershell.exe" AND NOT Process_Command_Line IN ([list of keywords to be avoided]) | stats count by New_Process_Name, Process_Command_Line```

As an example, let’s say your security product is called BlackPerl and runs Powershell scripts out of C:\Program Files\BlackPerl\Tool Scripts\, and that there are a lot of scripts here. Here is how you would filter it out:

```sourcetype="WinEventLog" EventCode=4688 New_Process_Name="*powershell.exe" AND NOT Process_Command_Line IN (*BlackPerl\\Tool\ Scripts*) | stats count by New_Process_Name, Process_Command_Line```

You can use this filtering technique to filter more than one keyword or string in a single query. For example, let’s say you have Monitoring Agent installed, and you’re sick of seeing it repeatedly in your Splunk results while zeroing in on unusual powershell.exe executions, but you also want to filter out the **BlackPerl** Tool Scripts directory. Simply add a comma for each keyword/string you want to filter on:

```sourcetype="WinEventLog" EventCode=4688 New_Process_Name="*powershell.exe" AND NOT Process_Command_Line IN (*BlackPerl\\Tool\ Scripts*, *Monitoring\ Agent*) | stats count by New_Process_Name, Process_Command_Line```

Similar sysmon query below:

```sourcetype="XmlWinEventLog:Microsoft-Windows-Sysmon/Operational" EventID=1 Image="*powershell.exe" AND NOT CommandLine IN (*BlackPerl\\Tool\ Scripts*, *Monitoring\ Agent*) | stats count by Image, CommandLine```

If you want to search for more than one executable in New_Process_Name/Image, but still want to keep the filters you set up via Process_Command_Line/CommandLine field, below query can be used:

```sourcetype="WinEventLog" EventCode=4688 AND New_Process_Name IN (*cscript.exe, *cmd.exe, *powershell.exe) AND NOT Process_Command_Line IN (*BlackPerl\\Tool\ Scripts*, *Microsoft\ Monitoring\ Agent*) | stats count by New_Process_Name, Process_Command_Line```

Here is a similar query for sysmon users that works identically:

```sourcetype="XmlWinEventLog:Microsoft-Windows-Sysmon/Operational" EventID=1 AND Image IN (*powershell.exe, *cmd.exe, *cscript.exe) AND NOT CommandLine IN (*BlackPerl\\Tool\ Scripts*, *Monitoring\ Agent*) | stats count by Image, CommandLine```

### Warning about Filtering Data

Some advanced adversaries can and will take advantage of overly permissive filters in order to operate in the margins. A lot of advanced adversaries will execute tools out of directories containing antivirus tools, or rename their tools to make them appear to be legitimate.

**Option1**: Use an overly broad filter to filter out all results containing the string **Monitoring Agent**. Then, once your investigation is complete, formulate a new query focusing exclusively on results from **Monitoring Agent**. Let’s start with both WinEventLog and Sysmon examples:

- ```sourcetype="WinEventLog" EventCode=4688 AND New_Process_Name IN (*Monitoring\ Agent*) | stats count by New_Process_Name, Process_Command_Line```
- ```sourcetype="XmlWinEventLog:Microsoft-Windows-Sysmon/Operational" EventID=1 AND Image IN (*Monitoring\ Agent*) | stats count by Image, CommandLine```

These queries are going to return all results with process names that include **Monitoring Agent**. This filter will work for examining binaries that run from that directory, but if the **Monitoring Agent** uses cscript or powershell to run scripts for various purposes, you may need to use the Process_Command_Line/CommandLine field instead. Here are queries for WinEventLog and Sysmon, respectively:

- ```sourcetype="WinEventLog" EventCode=4688 AND Process_Command_Line IN (*Monitoring\ Agent*) | stats count by New_Process_Name, Process_Command_Line```
- ```sourcetype="XmlWinEventLog:Microsoft-Windows-Sysmon/Operational" EventID=1 AND CommandLine IN (*Monitoring\ Agent*) | stats count by Image, CommandLine```

Also, you can use the OR operator to cover executables and/or scripts execution paths containing **Monitoring Agent** in a single query. Here are queries for WinEventLog and Sysmon:

- ```sourcetype="WinEventLog" EventCode=4688 AND (New_Process_Name IN (*Monitoring\ Agent*) OR Process_Command_Line IN (*Monitoring\ Agent*))  | stats count by New_Process_Name, Process_Command_Line```
- ```sourcetype="XmlWinEventLog:Microsoft-Windows-Sysmon/Operational" EventID=1 AND (Image IN (*Monitoring\ Agent*) OR CommandLine IN (*Monitoring\ Agent*)) | stats count by Image, CommandLine```


**Option2**: We can make our filter less broden simply by giving the exact path of the program that we want to avoid and giving the extention name of the file that we are looking for. Below are the examples:
- ```sourcetype="XmlWinEventLog:Microsoft-Windows-Sysmon/Operational" EventID=1 AND NOT Image IN (*Program\ Files*\\Monitoring\ Agent\\bin\\*) AND NOT CommandLine IN (*Program\ Files*\\Monitoring\ Agent\\scripts\\*) | stats count by Image, CommandLine```
- ```sourcetype=”WinEventLog” and EventCode=4688 AND NOT New_Process_Name IN (*Program\ Files*\Monitoring\ Agent\\bin\\*) AND NOT Process_Command_Line IN (*Program\ Files*\Monitoring\ Agent\\scripts\\*) | stats count by New_Process_Name, Process_Command_Line```
- ```sourcetype="XmlWinEventLog:Microsoft-Windows-Sysmon/Operational" EventID=1 AND NOT Image IN (*Program\ Files*\Monitoring\ Agent\\bin\\*.exe) AND NOT CommandLine IN (*Program\ Files*\\Monitoring\ Agent\\scripts\\*.ps*) | stats count by Image, CommandLine```
- ```sourcetype=”WinEventLog” and EventCode=4688 AND NOT New_Process_Name IN (*Program\ Files*\\Monitoring\ Agent\\bin\\*.exe) AND NOT Process_Command_Line IN (*Program\ Files*\\Monitoring\ Agent\\scripts\\*.ps*) | stats count by New_Process_Name, Process_Command_Line```


## Conclusion

In this repo, we have covered the basic hunt againt process creation focusing on queries you can use in Splunk to interrogate your process creation logs. We also took a bit of time to describe different strategies you can use to filter out benign results from your queries in order to reduce the volume of data analysts have to sift through. Finally, we discussed some hypotheses and specific questions you can use to guide hunting through your process creation logs. We will come up with a actual real usecase and show this practically in Splunk. Stay Tuned!

