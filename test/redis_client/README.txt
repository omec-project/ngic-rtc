
Please follow below guidline to execute redis test script:
----------------------------------------------------------

1. Install below packages

   cmd:
   ----
   1. sudo apt-get install python-pip
   2. sudo pip install pytz
   3. sudo pip install redis


2. Execute below command to trigger execution

   cmd: python redis_client.py <SERVER_IP> <PORT_NUM>

   Example:
   --------
   python redis_client.py 10.73.80.113 6379

   Note: Update Ip and Port with your respective database server


3. Once the execution will over, the .csv file will be generated inside the log directory which consist of CDR list associated with the selected CP.
