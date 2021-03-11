/*
 * Copyright (c) 2020 Sprint
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *      http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */


#include <iostream>
#include <stdint.h>
#include <dlfcn.h>

#include "epctools.h"
#include "emgmt.h"
#include "efd.h"
#include "estats.h"
#include "esynch.h"
#include "etevent.h"
#include "emgmt.h"
#include "elogger.h"

#include "DAdmf.h"

#define __file__ (strrchr(__FILE__, '/') ? strrchr(__FILE__, '/') + 1 : __FILE__)

configurations_t config;
ue_defaults_t ue_default;

int
ReadConfigurations(EGetOpt opt)
{
	config.dadmfIp = opt.get("/DAdmfApplication/DAdmfIP", "");
	config.dadmfPort = (opt.get("/DAdmfApplication/DAdmfPort", ZERO));

	config.admfIp = opt.get("/DAdmfApplication/AdmfIP", "");
	config.admfPort = (opt.get("/DAdmfApplication/AdmfPort", ZERO));
	config.ackCheckTimeInMin = (opt.get("/DAdmfApplication/AckCheckTimeInMin", 
			ZERO));

	ue_default.s11 = (opt.get("UeDefaultValues/s11", ZERO));
	ue_default.sgw_s5s8c = (opt.get("UeDefaultValues/sgw-s5s8c", ZERO));
	ue_default.pgw_s5s8c = (opt.get("UeDefaultValues/pgw-s5s8c", ZERO));
	ue_default.sxa = (opt.get("UeDefaultValues/sxa", ZERO));
	ue_default.sxb = (opt.get("UeDefaultValues/sxb", ZERO));
	ue_default.sxasxb = (opt.get("UeDefaultValues/sxasxb", ZERO));
	ue_default.s1u = (opt.get("UeDefaultValues/s1u", ZERO));
	ue_default.sgw_s5s8u = (opt.get("UeDefaultValues/sgw-s5s8u", ZERO));
	ue_default.pgw_s5s8u = (opt.get("UeDefaultValues/pgw-s5s8u", ZERO));
	ue_default.sgi = (opt.get("UeDefaultValues/sgi", ZERO));
	ue_default.s1u_content = (opt.get("UeDefaultValues/s1u_content", ZERO));
	ue_default.sgw_s5s8u_content = (opt.get("UeDefaultValues/sgw_s5s8u_content", 
			ZERO));
	ue_default.pgw_s5s8u_content = (opt.get("UeDefaultValues/pgw_s5s8u_content",
			ZERO));
	ue_default.sgi_content = (opt.get("UeDefaultValues/sgi_content", ZERO));
	ue_default.forward = (opt.get("UeDefaultValues/forward", ZERO));

	return RET_SUCCESS;
}

void
signal_handler(int signal)
{
	ELogger::log(LOG_SYSTEM).startup("Caught signal ({})", signal);

	switch (signal) {
		case SIGINT:
		case SIGTERM: {
			ELogger::log(LOG_SYSTEM).startup( \
				"Setting shutdown event");
			DAdmfApp *ptrInstance = (DAdmfApp::GetInstance());
			ptrInstance->setShutdownEvent();

			ptrInstance->ReleaseInstance();
			exit(RET_FAILURE);
			break;
		}
	}
}

void
init_signal_handler()
{
	sigset_t sigset;

	/* mask SIGALRM in all threads by default */
	sigemptyset(&sigset);
	sigaddset(&sigset, SIGRTMIN);
	sigaddset(&sigset, SIGUSR1);
	sigprocmask(SIG_BLOCK, &sigset, NULL);

	struct sigaction sa;

	/* Setup the signal handler */
	sa.sa_handler = signal_handler;

	/* Restart the system call, if at all possible */
	sa.sa_flags = SA_RESTART;

	/* Block every signal during the handler */
	sigfillset(&sa.sa_mask);

	if (sigaction(SIGINT, &sa, NULL) == -1)
		throw EError(EError::Warning, errno, 
		"Unable to register SIGINT handler");
	ELogger::log(LOG_SYSTEM).startup("signal handler registered "
					"for SIGINT");

	if (sigaction(SIGTERM, &sa, NULL) == -1)
		throw EError(EError::Warning, errno, 
		"Unable to register SIGTERM handler");
	ELogger::log(LOG_SYSTEM).startup("signal handler registered "
					"for SIGTERM");

	if (sigaction(SIGRTMIN + 1, &sa, NULL) == -1)
		throw EError(EError::Warning, errno, 
		"Unable to register SIGRTMIN handler");
	ELogger::log(LOG_SYSTEM).startup("signal handler registered "
					"for SIGRTMIN");
}

void
usage()
{
	cpStr msg =
	"USAGE:  d_admf [--print] [--help] [--file optionfile]\n";

	ELogger::log(LOG_SYSTEM).startup("%s", msg);
}

int
main(int argc, char *argv[])
{
	EGetOpt::Option options[] = {
		{"-h", "--help", EGetOpt::no_argument, EGetOpt::dtNone},
		{"-f", "--file", EGetOpt::required_argument, 
				EGetOpt::dtString},
		{"-p", "--print", EGetOpt::no_argument, EGetOpt::dtBool},
		{"", "", EGetOpt::no_argument, EGetOpt::dtNone},
	};

	EGetOpt opt;
	EString optfile;
	DAdmfApp *ptrInstance = NULL;

	try {
		opt.loadCmdLine(argc, argv, options);
		if (opt.getCmdLine("-h,--help", false)) {
			usage();
			return RET_SUCCESS;
		}

		optfile.format("%s.json", argv[ZERO]);
		if (EUtility::file_exists(optfile)) {
			opt.loadFile(optfile);
		}

		optfile = opt.getCmdLine("-f,--file", "__unknown__");
		if (EUtility::file_exists(optfile)) {
			opt.loadFile(optfile);
		}

		if (opt.getCmdLine("-p,--print", false))
			opt.print();

	} catch (const std::exception &e) {
		std::cerr << e.what() << '\n';
		ELogger::log(LOG_SYSTEM).startup("Exception: {}", e.what());
		return RET_FAILURE;
	}

	try {
		EpcTools::Initialize(opt);
		ELogger::log(LOG_SYSTEM).startup("EpcTools initialization complete");
		ELogger::log(LOG_SYSTEM).debug("[{}->{}:{}] ", __file__, 
				__FUNCTION__, __LINE__);

		init_signal_handler();
		ptrInstance = DAdmfApp::GetInstance();
	
		/* Read dadmf configuration file */
		ReadConfigurations(opt);

		ptrInstance->startup(opt);
		ptrInstance->waitForShutdown();

		ptrInstance->shutdown();

	} catch (const std::exception &e) {
		ELogger::log(LOG_SYSTEM).startup("Exception: {}", e.what());
		ptrInstance->ReleaseInstance();
		return RET_FAILURE;
        }

	return RET_SUCCESS;
}
