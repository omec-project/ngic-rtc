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


#include <dlfcn.h>

#include "elogger.h"

#include "AdmfApp.h"
#include "LegacyAdmfInterface.h"
#include "AdmfInterface.h"
#include "AdmfController.h"
#include "DAdmfInterface.h"


AdmfApplication g_app;

configurations_t config;
legacy_admf_intfc_config_t *legacy_config = new legacy_admf_intfc_config_t;

int
ReadConfigurations(EGetOpt &opt)
{
	inet_aton((opt.get("/AdmfApplication/DAdmfIp", EMPTY_STRING)), 
				&config.dadmfIp);

	config.dadmfPort = (opt.get("/AdmfApplication/DAdmfPort", ZERO));

	uint16_t admfPort = (opt.get("/AdmfApplication/AdmfPort", ZERO));

	config.admfPort = admfPort;

	inet_aton((opt.get("/AdmfApplication/LegacyInterfaceIp", EMPTY_STRING)), 
				&config.legacyInterfaceIp);

	inet_aton((opt.get("/AdmfApplication/AdmfIp", EMPTY_STRING)),
				&(legacy_config->admfIp));

	legacy_config->admfPort = admfPort;

	legacy_config->legacyAdmfPort = (opt.get("/AdmfApplication/LegacyAdmfPort",
				ZERO));

	inet_aton((opt.get("/AdmfApplication/LegacyAdmfIp", EMPTY_STRING)),
				&(legacy_config->legacyAdmfIp));

	legacy_config->legacyAdmfIntfcPort =
				(opt.get("/AdmfApplication/LegacyAdmfIntfcPort", ZERO));

	std::string protocol = (opt.get("/AdmfApplication/TransportProtocol",
				 TCP_PROT));

	if (protocol.compare(TCP_PROT))
		legacy_config->interfaceProtocol = legacy_admf_intfc_config_t::tcp;
	else if (protocol.compare(UDP_PROT))
		legacy_config->interfaceProtocol = legacy_admf_intfc_config_t::udp;
	else if (protocol.compare(REST_PROT))
		legacy_config->interfaceProtocol = legacy_admf_intfc_config_t::rest;

	return RET_SUCCESS;
}

void
signal_handler(int signal)
{
	ELogger::log(LOG_SYSTEM).startup("Caught signal ({})", signal);

	switch (signal) {
		case SIGINT:
		case SIGTERM: {
			ELogger::log(LOG_SYSTEM).startup(
				"Setting shutdown event");
			g_app.setShutdownEvent();
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
	"USAGE:  admf [--print] [--help] [--file optionfile]\n";

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
		ELogger::log(LOG_SYSTEM).startup("Exception: {}", e.what());
		return RET_FAILURE;
	}

	try {
		EpcTools::Initialize(opt);
		ELogger::log(LOG_SYSTEM).startup("EpcTools initialization "
						"complete");

		/* Load library */
		void *legacyInterface = dlopen("lib/libLegacyAdmfInterface.so", RTLD_LAZY);
		if (!legacyInterface) {
			ELogger::log(LOG_SYSTEM).info("Cannot load the library: {}", dlerror());
			return RET_FAILURE;
		}

		/* reset errors */
		dlerror();

		create_t* get_instance = (create_t*) dlsym(legacyInterface, "getInstance");
		const char* dlsym_error = dlerror();
		if (dlsym_error) {
			ELogger::log(LOG_SYSTEM).info("Cannot load symbol create: {}", dlsym_error);
			return RET_FAILURE;
		}

		destroy_t* release_instance = (destroy_t*) dlsym(legacyInterface, "releaseInstance");
		dlsym_error = dlerror();
		if (dlsym_error) {
			ELogger::log(LOG_SYSTEM).info("Cannot load symbol create: {}", dlsym_error);
			return RET_FAILURE;
		}

		BaseLegacyAdmfInterface *legacyAdmfIntfc = get_instance();

		legacyAdmfIntfc->ConfigureLogger(ELogger::log(LOG_SYSTEM_LEGACY));

		ReadConfigurations(opt);

		try {

			init_signal_handler();
			g_app.startup(opt, legacyAdmfIntfc);
			g_app.waitForShutdown();
			g_app.shutdown();
			release_instance(legacyAdmfIntfc);

		} catch (const std::exception &e) {
			ELogger::log(LOG_SYSTEM).major(e.what());
		}

		ELogger::log(LOG_SYSTEM).startup("Shutting down EpcTools");
		EpcTools::UnInitialize();

	} catch (const std::exception &e) {
		ELogger::log(LOG_SYSTEM).startup("Exception: {}", e.what());
		return RET_FAILURE;
	}

	return RET_SUCCESS;
}


void
AdmfApplication :: shutdown()
{
	mpAdmfInterface->ReleaseInstance();

	mpAdmfWorker->ReleaseInstance();

	mpDadmfInterface->ReleaseInstance();

	mpLegacyAdmfInterface->shutdown();
}

void
AdmfApplication::startup(EGetOpt &opt, BaseLegacyAdmfInterface *legacyAdmfIntfc)
{
	try {
		ELogger::log(LOG_SYSTEM).startup("Configuring LegacyInterface ");
      
		mpAdmfInterface = AdmfInterface::getInstance(*this, opt);
		mpAdmfInterface -> admfInit ();
      
		mpAdmfWorker = AdmfController :: getInstance(*this);
      
		mpDadmfInterface = DAdmfInterface :: getInstance(*this);

		setLegacyAdmfInterface(legacyAdmfIntfc);
		mpLegacyAdmfInterface->startup((void*)legacy_config);
	  
	} catch (FDException &e) {
		ELogger::log(LOG_SYSTEM).startup("Exception initializing instances - {}", e.what());
		return;
	} catch (...) {
		ELogger::log(LOG_SYSTEM).startup("Exception initializing Admf Application");
		return;
	}
}
