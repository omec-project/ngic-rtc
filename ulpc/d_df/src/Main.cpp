/*
 * Copyright (c) 2020 Sprint
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *
 * http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 **/

#include "Common.h"
#include "Controller.h"


struct Configurations config;


void
signal_handler(int signal)
{
	ELogger::log(LOG_SYSTEM).startup( "Caught signal ({})", signal );

	switch (signal) {
	case SIGINT:
	case SIGTERM:

		ELogger::log(LOG_SYSTEM).startup( "Setting shutdown event" );

		Controller * dFController = Controller::getInstance();
		dFController->setShutdownEvent();

		break;
	}
}


Void
init_signal_handler()
{
	sigset_t sigset;
	struct sigaction sa;

	sigemptyset(&sigset);
	sigaddset(&sigset, SIGRTMIN);
	sigaddset(&sigset, SIGUSR1);
	sigprocmask(SIG_BLOCK, &sigset, NULL);

	sa.sa_handler = signal_handler;

	sa.sa_flags = SA_RESTART;

	sigfillset(&sa.sa_mask);

	if (sigaction(SIGINT, &sa, NULL) == -1) {
		throw EError( EError::Warning, errno, "Unable to register SIGINT handler");
	}

	ELogger::log(LOG_SYSTEM).startup( "signal handler registered for SIGINT");

	if (sigaction(SIGTERM, &sa, NULL) == -1) {
		throw EError( EError::Warning, errno, "Unable to register SIGTERM handler");
	}

	ELogger::log(LOG_SYSTEM).startup( "signal handler registered for SIGTERM" );

	if (sigaction(SIGRTMIN+1, &sa, NULL) == -1) {
		throw EError( EError::Warning, errno, "Unable to register SIGRTMIN handler");
	}

	ELogger::log(LOG_SYSTEM).startup( "signal handler registered for SIGRTMIN" );
}


Void
usage()
{
	cpStr msg =
		"USAGE:  epc_app [--print] [--help] [--file optionfile]\n";

	std::cout << msg;
}


int32_t
read_configurations(EGetOpt &opt)
{
	config.df_port = opt.get("DdfAppliction/DfPort", 0);
	config.ddf_port = opt.get("DdfAppliction/DdfPort", 0);
	config.ddf_ip = opt.get("DdfAppliction/DdfIp", "undefined");
	config.df_ip = opt.get("DdfAppliction/DfIp", "undefined");
	config.strDModuleName = opt.get("DdfAppliction/NodeName", "undefined");
	config.strDFilePath = opt.get("DdfAppliction/PcapFilePath", "undefined");
	config.strDirName = opt.get("DdfAppliction/StorageDirName", "undefined");

	return RET_SUCCESS;
}


/**
 *   @brief   : Main function - Reads config file, initialise EPCLogger
 *              Creates thread calls startup function and
 *              waitForConnection to establish TCP connection
 *   @param1  : argc, number of arguments
 *   @param2  : argv, array of c-string arguments
 *   @return  : Returns 0
 **/

int32_t
main(int argc, char *argv[])
{
	EGetOpt::Option options[] = {
		{"-h", "--help", EGetOpt::no_argument, EGetOpt::dtNone},
		{"-f", "--file", EGetOpt::required_argument, EGetOpt::dtString},
		{"-p", "--print", EGetOpt::no_argument, EGetOpt::dtBool},
		{"", "", EGetOpt::no_argument, EGetOpt::dtNone},
	};

	EGetOpt opt;
	EString optFile;

	try {

		opt.loadCmdLine(argc, argv, options);
		if (opt.getCmdLine("-h,--help", false)) {

			usage();
			return 0;
		}

		optFile.format("%s.json", argv[0]);
		if (EUtility::file_exists(optFile)) {

			opt.loadFile(optFile);
		}

		optFile = opt.getCmdLine("-f,--file", "__unknown__");
		if (EUtility::file_exists(optFile)) {

			opt.loadFile(optFile);
		}

		if (opt.getCmdLine("-p,--print", false)) {

			opt.print();
		}
	}
	catch (const std::exception &e) {

		std::cerr << e.what() << '\n';
		ELogger::log(LOG_SYSTEM).startup("Exception: {}", e.what());
		return 1;
	}

	try {

		EpcTools::Initialize(opt);
		ELogger::log(LOG_SYSTEM).startup("EpcTools initialization complete" );

		try {

			init_signal_handler();
			read_configurations(opt);

			Controller * dFController = Controller::getInstance();

			dFController->startUp();
			dFController->waitForShutdown();
			dFController->shutdown();
		}
		catch(const std::exception& e) {

			ELogger::log(LOG_SYSTEM).major( e.what() );
		}

		ELogger::log(LOG_SYSTEM).startup("Shutting down EpcTools" );
		EpcTools::UnInitialize();
	}
	catch(const std::exception& e) {

		std::cerr << e.what() << '\n';
		return 2;
	}

	return RET_SUCCESS;
}
