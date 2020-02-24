#!/opt/support/python37/bin/python3
#############################################
## Author: Harikishan Mulagada
## Role  : Staff Engineer SteelCentral
##
##############################################

import os
import sqlite3
import zipfile
import tarfile
import json
import time
import re
import sys
import shutil
import datetime
from bokeh.plotting import figure, output_file, save
from bokeh.layouts import column
from bokeh.models.formatters import DatetimeTickFormatter

start = time.time()

##Unzip the diag bundle zip file
def unzip(filepath):

    filesizedict = {}
     
    extractpath = os.path.dirname(os.path.abspath(filepath))
    filename = os.path.basename(filepath)
       

    print('Unzipping bundle..')

    os.chdir(extractpath)

    if(filepath.endswith('.zip')):
        zfile = zipfile.ZipFile(filepath)
        zfile.extractall()
        try:
            for file_name in zfile.namelist():
                info = zfile.getinfo(file_name)
                if (float(info.file_size)/1000000)>10.0:
                    filesizedict.update({info.filename:float(info.file_size)/1000000})
        except Exception as e:
            print(e)

        zfile.close()
        unix_win_flag = 0
        
    else:
        tar = tarfile.open(filepath)
        tar.extractall()

        try:
            for info in tar.getmembers():
                if (float(info.size)/1000000)>10.0:
                    filesizedict.update({info.name:float(info.size)/1000000})
                    print(info.name)
                    print(float(info.size)/1000000)

        except Exception as e:
            print(e)

        tar.close()
        unix_win_flag = 1
        
    print('Finished unzipping the bundle...')

    try:
        if filename.find('.zip')!=-1:
            if filename.split('.zip')[0] in  os.listdir(extractpath):
                workdir = os.path.abspath(filename.split('.zip')[0])
            else:
                workdir = os.path.join(os.path.dirname(filepath),filename[filename.index('rpm_diag'):].split('.zip')[0])
                
        elif filename.find('.tar')!=-1:
            if filename.split('.tar')[0] in os.listdir(extractpath):
                workdir = os.path.abspath(filename.split('.tar')[0])
            else:
                workdir = os.path.join(os.path.dirname(filepath),filename[filename.index('rpm_diag'):].split('.tar')[0]).replace('rpm_diag-','rpm_diag.').replace('-MN-','.')

##    	if filename.split('.zip')[0] in  os.listdir(extractpath):
##        	workdir = os.path.abspath(filename.split('.zip')[0])
##        elif filename.split('.tar')[0] in  os.listdir(extractpath):
##		workdir = os.path.abspath(filename.split('.tar')[0])

    except Exception as e:
    	print(e)

    return workdir,unix_win_flag,filesizedict


##Delete all previously extracted folders
def cleanup(filepath,filename,errorandwarn,cpuplot):

    os.chdir(os.path.dirname(os.path.abspath(filepath)))

    if filepath.find('.zip')!=-1:
    	extrctdir = os.path.basename(filepath).split('.zip')[0]
    else:
	##extrctdir = os.path.basename(filepath).split('.tar')[0]
	##print(os.path.abspath(os.path.basename(filepath).split('.tar')[0]).replace('rpm_diag-','rpm_diag.').replace('-MN-','.'))
        extrctdir = os.path.abspath(os.path.basename(filepath).split('.tar')[0]).replace('rpm_diag-','rpm_diag.').replace('-MN-','.')

    cwd = os.getcwd()
##    cwd = os.chdir(os.path.dirname(os.path.abspath(filepath)))
##    print('Deleting folders...')

    for fdname in os.listdir(cwd):
        if (os.path.isdir(os.path.abspath(extrctdir))):
            print('Deleting folder',os.path.abspath(extrctdir))
            shutil.rmtree(os.path.abspath(extrctdir),ignore_errors=False)


    for fname in os.listdir(cwd):
        if ((fname.endswith('.txt') or fname.endswith('.html')) and (fname.find(filename)!=-1 or fname.find(errorandwarn)!=-1 or fname.find(cpuplot)!=-1)):
            print('Deleting file {0}'.format(fname))
            os.remove(fname)


##Function to set details when we have 4 arguments
def setdetails4(argv):
        try:
                if argv[1].isdigit():
                        if argv[2]!='':
                                path = argv[0]
                                casenum = argv[1]
                                errorandwarn = str(casenum)+'_'+str(argv[2])+'_errorsandwarns.txt'
                                filename = str(casenum)+'_'+str(argv[2])+'_agentdetails.txt'
                                title = str('AIX_logs_'+str(casenum)+'_'+str(argv[2])).rstrip()
                                cpuplot = str(casenum)+'_'+str(argv[2])+'_cpuplot.html'
                        else:
                                path = argv[0]
                                casenum = argv[1]
                                errorandwarn = str(casenum)+'_errorsandwarns.txt'
                                filename = str(casenum)+'_agentdetails.txt'
                                title = str('AIX_logs_'+str(casenum)).rstrip()
                                cpuplot = str(casenum)+'_'+str(argv[2])+'_cpuplot.html'
                else:
                        print('\nCase number should be numeric only')
                        print('Usage: python script_name path_to_diagbundle case_number <optional Desc>')
                        exit()

        except Exception as e:
                print(e)

        return path,casenum,filename,errorandwarn,title,cpuplot

##Function to set details when we have 3 arguments
def setdetails3(argv):
        try:
                if argv[1].isdigit():
                        path = argv[0]
                        casenum = argv[1]
                        errorandwarn = str(casenum)+'_errorsandwarns.txt'
                        filename = str(casenum)+'_agentdetails.txt'
                        title = str('AIX_logs_'+str(casenum)).rstrip()
                        cpuplot = str(casenum)+'_cpuplot.html'
                else:			
                        print('\nCase number should be numeric only')
                        print('Usage: python script_name path_to_diagbundle case_number <optional Desc>')
                        exit()

        except Exception as e:
                print(e)

        return path,casenum,filename,errorandwarn,title,cpuplot

##Function to generate weblinks for output files
def weblinks(WORK_DIR,path,filename,errorandwarn,cpuplot):
    try:
        baseURL = 'http://support.nbttech.com/'
        sysURL = ''
        errURL = ''
        pltURL = ''
        tmpPath = str(WORK_DIR.replace('/mnt/support/',baseURL))

        sysURL = tmpPath+'/'+filename
        errURL = tmpPath+'/'+errorandwarn
        pltURL = tmpPath+'/'+cpuplot
        logURL = tmpPath

        print('Creating Web Link to files...\n')
        print('*****************************\n')
        print('    WEB LINKS                \n')
        print('Browse Logs: '+logURL+'\n')
        print('Agent Details: '+sysURL+'\n')
        print('Errors log: '+errURL+'\n')
        print('CPU Plot: '+pltURL+'\n')
        print('\n*****************************\n')

    except Exception as e:
        print('Try passing full path to bundle instead on ./ or cd in /u/support/bin and run the script for weblinks')

def dsaversion(WORK_DIR):
        ver = ''
        ashost = ''
        try:
                FILE_TO_READ = os.path.abspath(WORK_DIR)+'/mn/data/dsa.xml'
                fobj = open(FILE_TO_READ)

                for line in fobj:
                        if line.find('<AgentVersion>')!=-1:
                                match = re.findall(r'[.\d]',line)
                        if line.find('<Attribute name="AnalysisServerHost" value=')!=-1:
                                ashost = line.split('value="')[1].replace('"/>','')

                for x in match:
                        ver = ver+x

                fobj.close()

        except Exception as e:
                print(e)


        return str(ver),ashost.strip()

def hostname(WORK_DIR):
	host_name = ''
	try:
		FILE_TO_READ = os.path.abspath(WORK_DIR)+'/commands/hostname'
		fobj = open(FILE_TO_READ)

		for line in fobj:
			host_name = line

		fobj.close()
		
	except Exception as e:
		print('Missing hostname file from bundle...')

	return host_name.strip()

def agentfqdn(WORK_DIR):
	fqdn = ''
	try:
		FILE_TO_READ = os.path.abspath(WORK_DIR)+'/mn/userdata/.fqdn.txt'
		fobj = open(FILE_TO_READ)

		lines = fobj.readlines()
		fqdn = lines[0]

		fobj.close()

	except Exception as e:
		print('Missing fqdn file from bundle...')

	return fqdn.strip()

def ipaddr(WORK_DIR):
	ip_addr = ''
	try:
		FILE_TO_READ = os.path.abspath(WORK_DIR)+'/commands/whichip'
		fobj = open(FILE_TO_READ)

		for line in fobj:
			if line.find('Selected IP Address:')!=-1:
				ip_addr = line.split(':')[1].strip()

		fobj.close()

	except Exception as e:
		print('Missing whichip file from bundle...')

	return ip_addr

def rpictrlstatus(WORK_DIR,UNIX_WIN_FLAG):
	rpictrl_status = ''
	try:
		if UNIX_WIN_FLAG == 0:
			FILE_TO_READ = os.path.abspath(WORK_DIR)+'/commands/rpictrl_status.txt'
		else:
			FILE_TO_READ = os.path.abspath(WORK_DIR)+'/commands/rpictrl_status'

		fobj = open(FILE_TO_READ)

		for line in fobj:
			if line.find('Status:')!=-1:
				rpictrl_status = line.split(':')[1].strip()

		fobj.close()

	except Exception as e:
		print('Missing rpictrl_status file from bundle...')

	return rpictrl_status

def rpictrljavainfo(WORK_DIR):
	rpictrl_java_info = ''
	try:
		FILE_TO_READ = os.path.abspath(WORK_DIR)+'/commands/rpictrl_java_info.txt'
		fobj = open(FILE_TO_READ)

		for line in fobj:
			if line.find('Java Injection:')!=-1:
				rpictrl_java_info = line.split(':')[1].strip()

		fobj.close()

	except Exception as e:
		print('Missing rpictrl_java_info file from bundle...')

	return rpictrl_java_info

def rpictrlnetinfo(WORK_DIR):
        rpictrl_net_info = ''
        try:
                FILE_TO_READ = os.path.abspath(WORK_DIR)+'/commands/rpictrl_net_info.txt'
                fobj = open(FILE_TO_READ)

                for line in fobj:
                        if line.find('.NET Injection:')!=-1:
                                rpictrl_net_info = line.split(':')[1].strip()

                fobj.close()

        except Exception as e:
                print('Missing rpictrl_net_info file from bundle...')

        return rpictrl_net_info


def rpictrlnetcoreinfo(WORK_DIR):
        rpictrl_netcore_info = ''
        try:
                FILE_TO_READ = os.path.abspath(WORK_DIR)+'/commands/rpictrl_netcore_info.txt'
                fobj = open(FILE_TO_READ)

                for line in fobj:
                        if line.find('.NET Core Injection:')!=-1:
                                rpictrl_netcore_info = line.split(':')[1].strip()

                fobj.close()

        except Exception as e:
                print('Missing rpictrl_netcore_info file from bundle...')

        return rpictrl_netcore_info

def apptraces(WORK_DIR,UNIX_WIN_FLAG):
	count = 0
	try:
		if UNIX_WIN_FLAG == 0:
			FILE_TO_READ = os.path.abspath(WORK_DIR)+'/commands/dir_a_s_q'
		else:
			FILE_TO_READ = os.path.abspath(WORK_DIR)+'/mn/ls_R_Panorama_mn'

		fobj = open(FILE_TO_READ)
		
		for line in fobj:
			if line.find('.apptrace')!=-1:
				count+=1
		fobj.close()
				
	except Exception as e:
		print('Missing dir_a_s_q/ls_R file from bundle...')

	return count		

def netstat(WORK_DIR):
        time_wait = 0
        close_wait = 0
        fin_wait = 0

        try:
                FILE_TO_READ = os.path.abspath(WORK_DIR)+'/commands/netstat_an'
                fobj = open(FILE_TO_READ)
                
                for x in fobj:
                        if(x.find('TIME_WAIT') and x.find('tcp')):
                                time_wait+=1
                        else:
                                if(x.find('CLOSE_WAIT') and x.find('tcp')):
                                        close_wait+=1
                                else:
                                        if(x.find('FIN_WAIT') and x.find('tcp')):
                                                fin_wait+=1

                fobj.close()

        except Exception as e:
            print('Missing netstat_an file from bundle...')

        return time_wait,close_wait,fin_wait            

def agentid(WORK_DIR):
	agent_id = ''
	try:
		FILE_TO_READ = os.path.abspath(WORK_DIR)+'/mn/userdata/.agent-id.txt'
		fobj = open(FILE_TO_READ)
		lines = fobj.readlines()

		agent_id = lines[0]

		fobj.close()

	except Exception as e:
		print('Missing agent-id file from bundle...')

	return agent_id

def agenttags(WORK_DIR):
	tags = ''
	try:
		FILE_TO_READ = os.path.abspath(WORK_DIR)+'/mn/userdata/config/tags.yaml'
		fobj = open(FILE_TO_READ)
		tags = fobj.readlines()

		fobj.close()

	except Exception as e:
		print('Missing tags.yaml file from bundle...')

	return tags


def configsavailable(WORK_DIR):
	configs = []
	try:
		DIR_TO_READ = os.path.abspath(WORK_DIR)+'/mn/userdata/config/'
		
		for files in os.listdir(DIR_TO_READ):
			if files.endswith('.json'):
				configs.append(files)
	except Exception as e:
		print(e)

	return configs

def processdetails(WORK_DIR,filename):
	processes = {}
	fwrite = open(filename,'a')
	try:
		FILE_TO_READ = os.path.abspath(WORK_DIR)+'/mn/userdata/jobs.json'
		fobj = open(FILE_TO_READ)
		
		processes = json.load(open(FILE_TO_READ))

		for x in processes['processmonikers']:
			fwrite.write('	ProcessMoniker: {0}\n'.format(x['processmoniker']))
			fwrite.write('	SHA-1: {0}\n'.format(x['sha-1']))
			fwrite.write('	AppType: {0}\n'.format(x['type']))

			for y in range(len(x['processes'])):
				fwrite.write('		Process Name: {0}\n'.format(x['processes'][y]['processname']))
				fwrite.write('		Process State: {0}\n'.format(x['processes'][y]['state']))
				fwrite.write('		Process PID: {0}\n\n'.format(x['processes'][y]['pid']))

		fwrite.close()

	except Exception as e:
		print(e)

	return


def envvar(WORK_DIR):
	env_var = []
	lookup_str = ['DOTNET_ADDITIONAL_DEPS','Path','PATH','COR_ENABLE_PROFILING','COR_PROFILER','PANORAMA_DOTNET_BIN','PANORAMA_LD_LIBRARY_PATH','PANORAMA_USERGROUP','USER']
	try:
		FILE_TO_READ = os.path.abspath(WORK_DIR)+'/commands/set'
		fobj = open(FILE_TO_READ)

		for line in fobj:
			for x in range(len(lookup_str)):
				if lookup_str[x] in line:
					env_var.append(line)
		fobj.close()
		
	except Exception as e:
		print(e)


	return env_var


def connectionstatus(WORK_DIR):
	counter = -1
	connection_status = ''
	connectiondetail = ''

	try:
		FILE_TO_READ = os.path.abspath(WORK_DIR)+'/mn/log/connection-status.txt'
		fobj = open(FILE_TO_READ,'r')

		lines = fobj.readlines()
		
		for x in range(0,len(lines)):
			if str(lines[counter:]).find('CONNECTION STATUS:')!=-1:
				match = 1
				connection_status = (lines[counter])
				break
			else:
				counter = counter - 1
		fobj.close()

		connectiondetail = connection_status.split('CONNECTION STATUS:')[1].strip()

	except Exception as e:
		print(e)
	
	return connectiondetail

def hs_err_pid(WORK_DIR):
	try:
		folder_to_read =os.path.abspath(WORK_DIR)+'/mn/log/'
		hserr_dict = {}

		file_list = (os.listdir(folder_to_read))

		for x in file_list:
			if (os.path.abspath(x).find('hs_err_pid')!=-1):
				hserr_dict.update({folder_to_read+x:time.ctime(os.path.getctime(os.path.abspath(folder_to_read+x)))})

	except Exception as e:
		print(e)

	return hserr_dict

def validatedotnetinfo(WORK_DIR):
	permcounter = 0
	try:
		FILE_TO_READ = os.path.abspath(WORK_DIR)+'/mn/support/ValidateDotNetInstall.log'
		fobj = open(FILE_TO_READ,'r')

		for line in fobj:
			if (line.find('No read access granted')!=-1 or line.find('No execute access granted')!=-1):
				permcounter+=1
		fobj.close()	

	except Exception as e:
		print('Missing ValidateDotNetInstall.log from bundle...')

	return permcounter

def dotnetcoreinfo(WORK_DIR):
	dotnetcoreversion = ''
	try:
		FILE_TO_READ = os.path.abspath(WORK_DIR)+'/commands/dotnet_info'
		fobj = open(FILE_TO_READ)

		lines = fobj.readlines()

		for line in lines:
			if line.find('Version:')!=-1:
				dotnetcoreversion = line

	except Exception as e:
		print('Missing dotnet info file...')

	return dotnetcoreversion.strip()

def cpustatsplot(WORK_DIR,casenum,cpuplot):
        cpu_values = {}
        plt_name = cpuplot

        try:
                FILE_TO_READ = os.path.abspath(WORK_DIR)+'/mn/log/cpu-stats.txt'
                fobj = open(FILE_TO_READ)
                prog = re.compile('^(\d{2}\/\d{2}\/\d{4}[ ]\d{2}:\d{2}:\d{2}.\d{3}).*[ ](core_pct:)[ ]([0-9]+.[0-9]+)')

                for lines in fobj:
                    values_stage = prog.findall(lines)
                    date_key = datetime.datetime.strptime(values_stage[0][0], '%m/%d/%Y %H:%M:%S.%f')
                    if(values_stage[0][2].find(',')!=-1):
                        cpu_value = float(values_stage[0][2].replace(",", "."))
                    else:
                        cpu_value = float(values_stage[0][2])
                    if(date_key not in cpu_values.keys()):
                        cpu_values.update({date_key:cpu_value})
                    else:
                        tmp = cpu_values.get(date_key)+cpu_value
                        cpu_values.update({date_key:tmp})                        

                fobj.close()

                output_file(plt_name, title="DSA CPU")

                datetime_tick_formats = {
                    key: ["%a %b %d %H:%M:%S"]
                    for key in ("seconds", "minsec", "minutes", "hourmin", "hours", "days")}

                p = figure(title="DSA CPU Usage",plot_width=800, plot_height=350,x_axis_type="datetime")
                p.xaxis.axis_label="Time"
                p.yaxis.axis_label="CPU %"
                p.xaxis.formatter = DatetimeTickFormatter(**datetime_tick_formats)
                p.line(list(cpu_values.keys()),list(cpu_values.values()),line_width=2,color="red")

                save(p)
  
        except Exception as e:
                print(e)

def errorsandwarns(WORK_DIR,errorandwarn):
    os.chdir(WORK_DIR)
    folders_to_read = ['/mn/log/','/mn/temp/']
    lookup_str = ['FATAL','ERROR','WARN']
    fwrite = open(errorandwarn,'a')
    try:
        for x in range(len(folders_to_read)):
            cur_folder = (os.path.abspath(WORK_DIR)+folders_to_read[x])
            file_list = (os.listdir(cur_folder))

            for x in file_list:
                if os.path.isdir((os.path.abspath(cur_folder+x))):
                    print('Skip reading directory ',x)
                else:
                    print('Reading file ',os.path.abspath(cur_folder+x))
                    fwrite.write('\n***** {0} *****\n\n'.format(x))
                    fobj = open(os.path.abspath(cur_folder+x), encoding ='latin-1')
                    for lines in fobj:
                        for string in range(len(lookup_str)):
                            if lookup_str[string] in lines:\
                               fwrite.write(lines)
                    fobj.close()
                    
    except Exception as e:
        print(e)

##Main function
def main():
    global filename
    global errorandwarn
    cpuplot = ''

    if len(sys.argv)==4:
        try:
                path,casenum,filename,errorandwarn,title,cpuplot = setdetails4(sys.argv[1:])
        except Exception as e:
                print(e)
    elif len(sys.argv)==3:
        try:
                path,casenum,filename,errorandwarn,title,cpuplot = setdetails3(sys.argv[1:])
        except Exception as e:
                print(e)
    else:
        print('\nUsage: python script_name path_to_diagbundle case_number <optional Desc>')
        exit()

    email = str(casenum)+'@riverbedsupport.com'
    customer = 'Global Support'
    file_name = os.path.abspath(path)

    try:

        cleanup(path,filename,errorandwarn,cpuplot)
        WORK_DIR,UNIX_WIN_FLAG,FILE_SIZE_DICT = unzip(path)
    except Exception as e:
        print(e)

    DSA_VER,AS_HOST = dsaversion(WORK_DIR)
    HOST_NAME = hostname(WORK_DIR)
    FQDN = agentfqdn(WORK_DIR)
    IP_ADDR = ipaddr(WORK_DIR)
    AGENT_ID = agentid(WORK_DIR)
    TAGS = agenttags(WORK_DIR)
    CONFIGS = configsavailable(WORK_DIR)
    ENV_VAR = envvar(WORK_DIR)
    RPICTRL_STATUS = rpictrlstatus(WORK_DIR,UNIX_WIN_FLAG) 
    RPICTRL_JAVA_INFO = rpictrljavainfo(WORK_DIR)
    RPICTRL_NET_INFO = rpictrlnetinfo(WORK_DIR)
    RPICTRL_NETCORE_INFO = rpictrlnetcoreinfo(WORK_DIR)
    VALIDATE_DOTNET_INFO_PERMS = validatedotnetinfo(WORK_DIR)
    TIME_WAIT,CLOSE_WAIT,FIN_WAIT = netstat(WORK_DIR)
    CONNECTION_STATUS = connectionstatus(WORK_DIR)
    APPTRACES = apptraces(WORK_DIR,UNIX_WIN_FLAG)
    HS_ERR_PID_LOGS = hs_err_pid(WORK_DIR)
    DOTNETCOREINFO = dotnetcoreinfo(WORK_DIR)
    errorsandwarns(WORK_DIR,errorandwarn)
    cpustatsplot(WORK_DIR,casenum,cpuplot)    

    #To create output files in extracted directory
    os.chdir(WORK_DIR)

    try:
        fwrite = open(filename,'a')
        fwrite.write('****** Agent Details ******\n')
        fwrite.write('Agent Name: {0}\n'.format(HOST_NAME))
        fwrite.write('Agent FQDN: {0}\n'.format(FQDN))
        fwrite.write('Agent IP: {0}\n'.format(IP_ADDR))
        fwrite.write('Agent Version: {0}\n'.format(DSA_VER))
        fwrite.write('Agent IID: {0}'.format(AGENT_ID))
        fwrite.write('Analysis Server Host: {0}\n'.format(AS_HOST))
        fwrite.write('Agent Tags:\n')
        for x in range(len(TAGS)):
            fwrite.write('	{0}'.format(TAGS[x]))
            
        fwrite.close()
        fwrite = open(filename,'a')
        fwrite.write('\n***** Found {0} files with size more than 10MB.\n'.format(len(FILE_SIZE_DICT)))
        fwrite.close()

        fwrite = open(filename,'a')
        try:
            if (DOTNETCOREINFO!=''):
                fwrite.write('\n***** Dotnet Core Details *****\n')
                fwrite.write(DOTNETCOREINFO+'\n')

            if float(DOTNETCOREINFO.split(':')[1])>=3.0:
                fwrite.write('\nIf customer is not running agent version greater than equal to 10.21.7, they will run in to APMDEV-2866\n')
                fwrite.write('Please look into the JIRA bug which prevents instrumentation older dotnet core applications when dotnetcore 3.x is installed\n')

        except Exception as e:
           print(e)

        fwrite.close()

        fwrite = open(filename,'a')
        fwrite.write('\n***** Instrumentation Details *****\n')
        fwrite.write('RPICTRL Status: {0}\n'.format(RPICTRL_STATUS))
        fwrite.write('RPICTRL Java Status: {0}\n'.format(RPICTRL_JAVA_INFO))
        fwrite.write('RPICTRL .NET Status: {0}\n'.format(RPICTRL_NET_INFO))
        fwrite.write('RPICTRL .NET Core Status: {0}\n'.format(RPICTRL_NETCORE_INFO))
        fwrite.write('Process details:\n')
        fwrite.close()

        processdetails(WORK_DIR,filename)

        fwrite = open(filename,'a')
        if VALIDATE_DOTNET_INFO_PERMS > 0:
                fwrite.write('\n****** Validate DotNet Install information *****\n')
                fwrite.write('Read/Execute permission errors {0}\n'.format(VALIDATE_DOTNET_INFO_PERMS))
                fwrite.write('Look into ValidateDotNetInstall log for more details\n\n')

        fwrite.close()

        fwrite = open(filename,'a')
        if APPTRACES>0:
                fwrite.write('***** Found at least {0} apptraces on the agent\n'.format(APPTRACES))
        else:
                fwrite.write('***** Found no apptraces on the agent or missing details from bundle\n')

        fwrite.write('\n****** Configuration and other details ******\n')
        fwrite.write('Available Configuration list:\n')
        for x in range(len(CONFIGS)):
                fwrite.write('            {0}\n'.format(CONFIGS[x]))

        fwrite.write('\nEnvironment Variables:\n')
        for x in range(len(ENV_VAR)):
                fwrite.write('          {0}'.format(ENV_VAR[x]))
    
        fwrite.write('\n***** Netstat details *****\n')
        fwrite.write('TIME_WAITs: {0}\n'.format(TIME_WAIT))
        fwrite.write('CLOSE_WAITs: {0}\n'.format(CLOSE_WAIT))
        fwrite.write('FIN_WAITs: {0}\n'.format(FIN_WAIT))
 
        fwrite.close()
 
        fwrite = open(filename,'a')
        fwrite.write('\n***** LAST CONNECTION STATUS *****\n')
        fwrite.write(CONNECTION_STATUS)
        fwrite.close()

        if len(FILE_SIZE_DICT)>0:
                fwrite = open(filename,'a')
                fwrite.write('\n\n***** List of logs with size greater than 10MB ******\n')
                for key,value in FILE_SIZE_DICT.items():
                        fwrite.write('{0} - {1} MB\n'.format(key,value))
                fwrite.close()

        if len(HS_ERR_PID_LOGS)>0:
                fwrite = open(filename,'a')
                fwrite.write('\n***** Found hs_err_pid logs *****\n')
                fwrite.write('Found {0} hs_err_pid logs.\n'.format(len(HS_ERR_PID_LOGS)))
                fwrite.write('Please take a look which process coredumped\n')
                fwrite.write('Please take a look at _errorsandwarns.txt for list of files and creation date\n')
                fwrite.close()

                fwrite = open(errorandwarn,'a')
                fwrite.write('\n***** List of hs_err_pid files *****\n')
                for key,value in HS_ERR_PID_LOGS.items():
                        fwrite.write('{0} - {1}\n'.format(key,value))

                fwrite.close()
        
    except Exception as e:
        print(e)
	
    weblinks(WORK_DIR,path,filename,errorandwarn,cpuplot)

    end = time.time()

    print('Took '+str(end-start)+'s'+' for the script to finish.... ')

if __name__=="__main__":
	main()

