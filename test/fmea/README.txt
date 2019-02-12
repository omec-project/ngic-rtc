-----------------------------------------------------------------------
FMEA TEST SCRIPT :- test_fmea.sh

Description:- This test script is used to validate FMEA test cases.
              also it can be used to run user defined test cases.

---------------------------------------------------------------------
1.1 Configuration:-

Before running script ensure that all parameters in following files
filled correctly.
Description of each parameter is given in respective file.

1.host_config.cfg:-This file will be used to lauch application on
                   respective physical machine or VM.It contain
                   parameter like VM name,password,home directory
                   location etc.

2.test.cfg:-This file will be used for actual test case parameter
            like FLOWS (i.e no. of UE's) tps & pps.
            it also contain sequence in which test cases are performed.
NOTE:- To performm fmea test cases copy fmea_test.cfg to test.cfg from
       current directory.

------------------------------------------------------------------------
2.1 Run test script :-

Script can be run by following ways:-

1)./test_fmea.sh :- fmea test cases for dp is performed

2)./test_fmea.sh <test no> :- run particular test case only.
                                 by default it will run only single instance
                                 of given test case.
                                 for eg. ./test_fmea.sh 3
                                 it will run test case 3 for one time

3)./test_fmea.sh <test no> <no of iteration> :- run particular test case for
                                                   given no of time.
                                                   for eg. ./test_fmea.sh 3 2
                                                   it will run test case 3 for 2
                                                   time.

-------------------------------------------------------------------------------
3.1 Report folder :-

After running test script report is generated into folder name "reports"
it contail single csv file & log folder.
csv file contain summary of test performed.
log folder contain log for each test case.

------------------------------------------------------------------------------------











