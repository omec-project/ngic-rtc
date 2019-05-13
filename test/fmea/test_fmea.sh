#!/bin/bash
#Usage: ./ngicperf.sh
#Ensure that all the values are filled correctly in host_config.cfg file in the current directory.
#Please refer test.cfg file for the various test cases.

#Prerequisite :::
#sshpass and perf


#Source configuration
source host_config.cfg
source test.cfg
source pass_criteria.cfg

csv_reports_path="csv-reports"

ARG_LEN=$#
ARG_1=$1
ARG_2=$2

#Main function invoke
function main(){



	#Check dependencies..
	command -v sshpass >/dev/null 2>&1 || {
	      echo >&2 "I require sshpass but it's not installed."
		  read -p "Do you wish to install this program?" yn;
          case $yn in
			   [Yy]* ) apt-get install sshpass; break;;
			   [Nn]* ) exit;;
	            * ) echo "Please answer yes or no.";;
		  esac
	}

	 command -v bc >/dev/null 2>&1 || {
	      echo >&2 "I require bc but it's not installed."
		  read -p "Do you wish to install this program?" yn;
		  case $yn in
			  [Yy]* ) apt-get install bc; break;;
			  [Nn]* ) exit;;
			   * ) echo "Please answer yes or no.";;
		  esac
	}




	#Initialize trap to call cleanup function when ctrl_c received
    trap ctrl_signal INT TERM

	echo -e "\nDeleting existing reports folders and creating new...\n"
	rm -rf reports

         CSV_HEADER_FLAG=0

         fmea_test_1_flag=0
		 fmea_test_2_flag=0

		 if [[ $ARG_LEN -eq 0 ]]
		 then
	     fmea_test_1_flag=1
		 fmea_test_2_flag=1
		 ARG_LEN=0
	     fi

         if [[ $ARG_LEN -eq 0  ]]
         then
                  cnt=0
                  while [[ $cnt -lt ${#TEST_SEQ[@]} ]]
                  do
                     TEST_NO=${TEST_SEQ[$cnt]}
					 (( cnt++ ))
                     REPEAT_COUNT=${TEST_SEQ[$cnt]}
					 (( cnt++ ))
					 RST_FLAG=${TEST_SEQ[$cnt]}
					 if [[ $TEST_NO -eq 1 ]]
					 then
                          start_dp
				     else
						 start_test
				     fi
					 ((cnt++))
                  done
         else

               case $ARG_1 in
                       dp|DP)
                            test_one
                            ;;
                           *)
                              if [[ $ARG_1 -le $NO_OF_TEST ]]
                              then
                                  TEST_NO=$ARG_1
								  if [[ $ARG_2 -eq 0 ]]
								  then
		                          REPEAT_COUNT=1
							      else
									  REPEAT_COUNT=$ARG_2
								  fi
                                  start_test
                              else
                                   echo "Invalid option"
                                   echo "Give option in range 1 to $NO_OF_TEST"
								   exit
                              fi
                              ;;
                esac
          fi

		  #arrange in single directory structure.
		  mkdir -p reports
		  mkdir -p reports/log
          mv TEST_CASE_* ./reports/log
		  mv csv-reports/*.csv reports
		  rm -rf csv-reports
		  exit

}



function start_test(){

flows=$(cat test.cfg | grep -i -A 3 "TEST_NO=$TEST_NO" | grep -i FLOWS | cut -d '=' -f 2 | awk '{print $1}')
tps=$(cat test.cfg | grep -i -A 3 "TEST_NO=$TEST_NO" | grep -i TPS | cut -d '=' -f 2| awk '{print $1}')
pps=$(cat test.cfg | grep -i -A 3 "TEST_NO=$TEST_NO" | grep -i PPS | cut -d '=' -f 2 | awk '{print $1}')
#RST_FLAG=$(cat test.cfg | grep -i -A 4 "TEST_NO=$TEST_NO" | grep -i RESTART_FLAG | cut -d '=' -f 2 | awk '{print $1}')


	IFS=', ' read -r -a flows_arr <<< "$flows"
	IFS=', ' read -r -a pps_arr <<< "$pps"

    for flows_index in "${!flows_arr[@]}"
	do
	for pps_index in "${!pps_arr[@]}"
	do

	set_instances_env
	{
		run_tests
	} &&{
	echo -e "Successfully completed test for ${flows_arr[flows_index]} flows and ${pps_arr[pps_index]} pps"
	} ||{
		echo -e "Failed to run tests..\n"
		cleanup
		pkill screen
	}
    done
    done

}


#Function, start test runs  one by one
function run_tests(){

	count=1
	while [ $count -le $REPEAT_COUNT ]
	do
		echo "-------------------------------------------------------------------"
	    echo "TEST_CASE N0:$TEST_NO "
		echo "INSTANCE COUNT:$count of $REPEAT_COUNT"
		echo "NO.OF UE's:-${flows_arr[flows_index]} flows"
		echo "PPS:-${pps_arr[pps_index]} "
		echo "TPS:-$tps "
		echo ""


		{
		    start_il_nperf
		}


		if [[ $count -eq 1 || $RST_FLAG -eq 1   ]]
		then
			{
			start_dp
                }&& {
                        start_cp

		}||{
			cleanup
			pkill screen
		}
	    fi

		if [ $TEST_NO -gt 2 ]
		then

		#Start dp, nperf generator and receiver
		echo "Starting sending and receiving packets..."
		start_sending_receiving_packets


		#Wait for test complete, then stop event occure.
		echo -e "Waiting $(expr 15 \+ $il_nperf_test_duration) second before sending quit to il-nperf...\n"
		sleep $(expr 15 \+ $il_nperf_test_duration)

		cleanup


		generate_csv_report
		rm -f screenlog.0


		sleep 5
	    fi
		count=$[$count+1]
	done

	echo "--------- TEST FINISHED---------------"

}


#Init data-plane and il_nperf
function set_instances_env(){


    echo "----------------------------------------------------------------"
	echo ""
	echo -e "\nUpdating user_input.cfg file of il-nperf for new pps and flows values"

    cp_break_duration=$(expr $il_nperf_test_duration + 10 )

	update_test_duration="sed -i -e '/test_duration=/s/=.*/=$il_nperf_test_duration/' user_input.cfg"
	update_cp_test_duration="sed -i -e '/BREAK_DURATION=/s/=.*/=$cp_break_duration/' simu_cp.cfg"
    update_flows="sed -i -e '/flows=/s/=.*/=${flows_arr[flows_index]}/' user_input.cfg"
	update_pps="sed -i -e '/pps=/s/=.*/=${pps_arr[pps_index]}/' user_input.cfg"
    update_flows_in_cp="sed -i -e '/MAX_UE_SESS=/s/=.*/=${flows_arr[flows_index]}/' simu_cp.cfg"
    update_tps="sed -i -e '/TPS/s/=.*/=$tps/' simu_cp.cfg"



	#Source dp's setenv and update init.c
	echo -e "Sourcing setenv script of dataplane\n"
    screen  -S ngic_dataplane -d -m ssh -i /root/.ssh/id_rsa root@$DP_VM_NAME 'cd '$dp_home_dir';source setenv.sh;'


    echo -e "Updating TPS parameter in simu_cp.cfg in CP... \n"
    screen  -S ngic_controlplane -d -m ssh -i /root/.ssh/id_rsa root@$CP_VM_NAME 'cd '$cp_home_dir';cd ../config;'$update_tps';'

	echo -e "Updating flows in simu_cp.cfg\n"
ssh -i /root/.ssh/id_rsa $VM_LOGIN_NAME@$CP_VM_NAME 'cd '$cp_home_dir';cd ../config;'$update_flows_in_cp';'$update_cp_test_duration';'

	echo -e "Updating flows and pps parameter in user_input.cfg ...\n"

       #Source il-nperf's setenv and update user_input.cfg
       sshpass -p $password ssh $nperf_generator 'cd '$il_nperf_home_dir'\
	   ;source setenv.sh;cd pktgen/autotest;'$update_flows';'$update_pps';'$update_test_duration';'
    echo "----------------------------------------------------------------------"
	echo ""
	   sleep 5

}


#Function, start and ensure dataplane started succesfully.
function start_dp(){

	echo "Starting Data-plane..."
	rm -f screenlog.0

    screen -L -S ngic_dataplane -d -m ssh -i /root/.ssh/id_rsa $VM_LOGIN_NAME@$DP_VM_NAME 'cd '$dp_home_dir';./run.sh log;'

	sleep $session_duration
	sleep 10

	#Ensure DP has been started successfully.
    eval $check_dp_start_command


	if [ $? -eq $dp_start_verify ]; then
		echo -e "Data-plane started successfully...\n"
        success_dp_flag=1
	else
		echo -e "Failed to start Data-plane!!!. Exiting ...\n"
		success_dp_flag=0
	fi

	if [ $fmea_test_1_flag -eq 0 ] && [ $success_dp_flag -eq 0 ]
	then
		cleanup
		pkill screen
		exit
	fi
	screen -S ngic_dataplane -X log off
	rm -f screenlog.0

   if [ $fmea_test_1_flag -eq 1 ]
   then
	    if [ $success_dp_flag -eq 1 ]
		then
		echo " "
		echo "TEST_CASE_1:PASS"
		echo " "
        fmea_test_1_flag=0
   		echo -e "Stopping Data-Plane..."
   		ssh -i /root/.ssh/id_rsa "$VM_LOGIN_NAME"@$DP_VM_NAME  'killall ngic_dataplane'
   		ssh -i /root/.ssh/id_rsa "$VM_LOGIN_NAME"@$DP_VM_NAME  'killall run.sh'
   		screen -S ngic_dataplane -X stuff ^C
   		echo -e "Sent Ctrl c signal to dataplane...\n"
    	else
			fmea_test_1_flag=0
			echo ""
			echo "TEST_CASE_1:FAIL"
			echo ""
			screen -S ngic_dataplane -X stuff ^C
		fi
		count=1
		generate_csv_report
   fi
}

function start_cp(){

	echo  "Starting Control-plane..."
	rm -f screenlog.0

   screen -L -S ngic_controlplane -d -m ssh -i /root/.ssh/id_rsa $VM_LOGIN_NAME@$CP_VM_NAME 'cd '$cp_home_dir';./run.sh log;'

	sleep 15


	#Ensure CP has been started successfully.
	ssh -i /root/.ssh/id_rsa "$VM_LOGIN_NAME"@$CP_VM_NAME  'ps -aeldf | grep -v grep | grep -w ngic_controlplane' >/dev/null


	eval $check_cp_start_command

	if [ $? -eq $cp_start_verify ]; then
		echo -e "Control-plane started successfully...\n"
		cp_success_flag=1
	else
		echo -e "Failed to start Control-plane!!!. Exiting ...\n"
		cp_success_flag=0
	fi

	if [ $fmea_test_2_flag -eq 0 ] && [ $cp_success_flag -eq 0 ]
	then
		cleanup
		pkill screen
		exit
	fi


	if [ $TEST_NO -ne 4 ]
	then
        echo "Waiting to create sessions ${flows_arr[flows_index]} by cp on dp ..."
		SESSION_NO=$(tail -n 1 screenlog.0 | awk '{print $7}')
		while [[ $SESSION_NO -ne ${flows_arr[flows_index]}  ]]
		do
			sleep 5
			SESSION_NO=$(tail -n 1 screenlog.0 | awk '{print $7}')
		done
		sleep 10

		echo "Sessions created by cp"
		NUM_CS_FAILED=$( eval $check_num_cs_command )
		NUM_CS_FAILED=${NUM_CS_FAILED//[[:blank:]]/}
		NUM_CS_FAILED=$(echo $NUM_CS_FAILED | tr -d '\r')
		NUM_MB_FAILED=$( eval $check_num_mb_command )
		NUM_MB_FAILED=${NUM_MB_FAILED//[[:blank:]]/}
		NUM_MB_FAILED=$(echo $NUM_MB_FAILED | tr -d '\r')


		if [ $NUM_CS_FAILED == 0 ] && [ $NUM_MB_FAILED == 0 ]
		then
			echo "sessions establish on dp successfully"
			session_success_flag=1
		else
    		echo "sessions failed to establish on dp"
			session_success_flag=0
    	fi


		if [ $fmea_test_2_flag -eq 0 ] && [ $session_success_flag -eq 0 ]
    	then
			cleanup
			exit
		fi

		if [ $fmea_test_2_flag -eq 1 ]
		then
		 	if [ $session_success_flag -eq 1 ]
		 	then
			 	echo ""
			 	echo "TEST_CASE_2:PASS"
			 	echo ""
	     	else
			 	echo ""
			 	echo "TEST_CASE_2:FAIL"
			 	echo ""
		 	fi
			fmea_test_2_flag=0
			generate_csv_report
			cleanup
	 	fi
	else
		sleep 10
    fi

	screen -S ngic_controlplane -X log off >/dev/null
	rm -f screenlog.0

}


#Function, start and ensure il-nperf started successfully
function start_il_nperf(){

	echo "Starting il-nperf generator..."
	rm -f screenlog.0
screen  -S nperf_generator -d -m sshpass -p $password ssh -t $nperf_generator 'cd '$il_nperf_home_dir';cd pktgen;./il_nperf.sh -g;'

	sleep 30

	#Ensure inperf-generator has been started successfully.
	sshpass -p $password ssh $nperf_generator 'ps -aeldf | grep -v grep | grep -w' \''il_nperf.sh -g'\' >/dev/null
	if [ $? -eq 0 ]; then
		echo -e "Il-nperf generator started successfully...\n"
	else
		echo -e "Failed to start il-nperf generator!!!. Exiting ...\n"
		cleanup
		pkill screen
		exit
	fi

	echo "Starting il-nperf receiver..."
	screen -S nperf_receiver -d -m sshpass -p $password ssh -t $nperf_receiver 'cd '$il_nperf_home_dir'\
	;cd pktgen;./il_nperf.sh -r'

	sleep 10

	#Ensure inperf-receiver has been started successfully.
	sshpass -p $password ssh $nperf_receiver 'ps -aeldf | grep -v grep | grep -w' \''il_nperf.sh -r'\' >/dev/null


	if [ $? -eq 0 ]; then
		echo -e "Il-nperf receiver started successfully...\n"
	else
		echo -e "Failed to start il-nperf receiver!!!. Exiting...\n"
		cleanup
		pkill screen
		exit
	fi
}


#Function to trigger generator and receiver for start sending and receiving pkts.
function start_sending_receiving_packets(){

	#Send start 0 command to nperf generator.
	echo "Sent start 0 signal to nperf_generator"
	screen -S nperf_generator -p 0 -X stuff "start 0^M"
	sleep 1

	#Send start 0 command to nperf receiver.
	echo -e "Sent start 0 signal to nperf_receiver\n"
	screen -S nperf_receiver -p 0 -X stuff "start 0^M"
}


#Function to generate perf csv report headers.
function generate_csv_report_header(){

    declare -g csv_headers="TEST_SR_NO"


	csv_headers="$csv_headers,ITERATION, RESULT, LOG_FILE_FOLDER"
    pevents=""

	pevents=${pevents//[[:blank:]]/}
	csv_headers="$csv_headers$pevents"

    	declare -g csv_file_name="fmea""_$(date +"%Y-%m-%d_%H-%M").csv"
	mkdir -p $csv_reports_path
	echo -e "Creating $csv_file_name  in $csv_reports_path dir ...\n"

}


#Function to feed test value to csv report.
function generate_csv_report(){

	values="$TEST_NO,$count"
	if [[ $count -eq 1 ]]
	then
    echo "-------------------------------------------------------------------"
    echo "Generating log folder for test $TEST_NO name TEST_CASE_$TEST_NO"
    else
	echo "--------------------------------------------------------------------"
    fi

	if [[ $count -eq 1 ]]
	then
	mkdir -p TEST_CASE_$TEST_NO
    fi


	file_command="ls -t1 |  head -n 1"

	if [[ $TEST_NO -eq 1  || $# -ne 2 ]] && [[ $CSV_HEADER_FLAG -eq 0 ]]
	then
        CSV_HEADER_FLAG=1
		generate_csv_report_header

	    rm -f screenlog.0

		echo -e "\t#### System Under Test Report ####" >> $csv_reports_path/$csv_file_name
		echo "$csv_headers" >> $csv_reports_path/$csv_file_name
    fi

    if [[ $TEST_NO -gt 2 ]]
	then

      	#Get the last log file name of il nperf generator.
        il_nperf_file_to_copy=$(sshpass -p $password ssh $nperf_generator 'cd '$il_nperf_home_dir';cd pktgen/autotest/log;'$file_command';')

	    sleep 5

	    echo -e "\nCopying $il_nperf_file_to_copy from  nperf generator"

	    #Copy the last generated log file of il nperf generator
        sshpass -p $password scp $nperf_generator:$il_nperf_home_dir/pktgen/autotest/log/$il_nperf_file_to_copy TEST_CASE_$TEST_NO

        #clear log folder.
        sshpass -p $password ssh $nperf_generator 'cd '$il_nperf_home_dir';cd pktgen/autotest/log;rm -f *.log;'
     fi

    if [[ $count -eq 1 || $RST_FLAG -eq 1 ]]
    then

		if [[ $TEST_NO -ne 1 ]]
		then
             #Copy cp log file
             cp_file_to_copy=$(ssh -i /root/.ssh/id_rsa $VM_LOGIN_NAME@$CP_VM_NAME 'cd '$cp_home_dir';cd logs;'$file_command';')

	         echo -e "\n Copying $cp_file_to_copy from cp machine"
             scp $VM_LOGIN_NAME@$CP_VM_NAME:$cp_home_dir/logs/$cp_file_to_copy TEST_CASE_$TEST_NO
	         sleep 5

        	 #clear log folder
	         ssh -i /root/.ssh/id_rsa $VM_LOGIN_NAME@$CP_VM_NAME 'cd '$cp_home_dir';cd logs;rm -f *.log;'

        fi

        #Copy dp log file
	    dp_file_to_copy=$(ssh -i /root/.ssh/id_rsa $VM_LOGIN_NAME@$DP_VM_NAME 'cd '$dp_home_dir';cd logs;'$file_command';')


        echo -e "\n Copying $dp_file_to_copy from dp machine"
        scp $VM_LOGIN_NAME@$DP_VM_NAME:$dp_home_dir/logs/$dp_file_to_copy TEST_CASE_$TEST_NO
		sleep 5

        #clear log folder.
        ssh -i /root/.ssh/id_rsa $VM_LOGIN_NAME@$DP_VM_NAME 'cd '$dp_home_dir';cd logs;rm -f *.log;'
     fi

	 if [[ $TEST_NO -ge 3 ]]
	 then


	ul_pkt_loss=$(cat ./"TEST_CASE_$TEST_NO"/$il_nperf_file_to_copy | grep -i "UL" | cut -d ';' -f 2 | cut -d '.' -f 1 | awk '{print $1}')
    dl_pkt_loss=$(cat ./"TEST_CASE_$TEST_NO"/$il_nperf_file_to_copy | grep -i "DL" | cut -d ';' -f 2 | cut -d '.' -f 1 | awk '{print $1}')


    echo "UP_LINK_PACKET_LOSS:"$ul_pkt_loss
	echo "DOWN_LINK_PACKET_LOSS:"$dl_pkt_loss


    if [[ $ul_pkt_loss -le 5 ]] && [[ $dl_pkt_loss -le 5 ]]
	then
        values="$values,PASS"
		pass_flag=1
	else
        values="$values,FAIL"
		pass_flag=0
    fi

	 if [ $pass_flag -eq 1 ]
	 then
		 echo ""
		 echo "TEST_CASE_$TEST_NO : PASS"
		 echo ""
	 else
		 echo ""
		 echo "TEST_CASE_$TEST_NO : FAIL"
		 echo ""
	 fi

    fi

	if [[ $TEST_NO -eq 1 ]]
	then
		if [[ $success_dp_flag -eq 1 ]]
		then
             values="$values,PASS"
	    else
			 values="$values.FAIL"
        fi
	fi

	if [[ $TEST_NO -eq 2 ]]
	then
		if [[ $session_success_flag -eq 1 ]]
		then
			values="$values,PASS"
		else
			value="$values,FAIL"
		fi
	fi

    values="$values,./log/TEST_CASE_$TEST_NO"


   	echo -e "Added log data in $csv_file_name  ...\n"


	#Align indent i.e. Remove spaces
	values=${values//[[:blank:]]/}
	echo "$values" >> $csv_reports_path/$csv_file_name
}


function cleanup(){


   echo -e "Stopping Il_nperf generator..."
   screen -S nperf_generator -p 0 -X stuff "quit^M"
   echo -e "Sent quit to nperf_generator...\n"

   echo -e "Stopping Il_nperf receiver..."
   screen -S nperf_receiver -p 0 -X stuff "quit^M"
   echo -e "Sent quit to nperf_receiver...\n"

   if [[ $RST_FLAG -eq 1 || $count -eq $REPEAT_COUNT  ]]
   then
   echo -e "Stopping Control-Plane.."
   ssh -i /root/.ssh/id_rsa "$VM_LOGIN_NAME"@$CP_VM_NAME  'killall ngic_controlplane'
   ssh -i /root/.ssh/id_rsa "$VM_LOGIN_NAME"@$CP_VM_NAME  'killall run.sh'
   screen -S ngic_controlplane -X stuff ^C
   echo -e "Sent Ctrl c signal to controlplane..\n"

   echo -e "Stopping Data-Plane..."
   ssh -i /root/.ssh/id_rsa "$VM_LOGIN_NAME"@$DP_VM_NAME  'killall ngic_dataplane'
   ssh -i /root/.ssh/id_rsa "$VM_LOGIN_NAME"@$DP_VM_NAME  'killall run.sh'
   screen -S ngic_dataplane -X stuff ^C
   echo -e "Sent Ctrl c signal to dataplane...\n"
   fi
}

#Function to cleanup, when ctrl_c received
function ctrl_signal(){
   RST_FLAG=1
   cleanup
   pkill screen
   sleep 5
   rm -f lscpu.txt
   rm -f screenlog.0
   exit 2
}


function test_one(){

	start_dp

}


#Script start from here
main
