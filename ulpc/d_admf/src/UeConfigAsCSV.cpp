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


#include "Common.h"
#include "UeConfigAsCSV.h"
#include "DAdmf.h"


UeConfigAsCSV::UeConfigAsCSV()
{
}

UeConfigAsCSV::UeConfigAsCSV(const std::string &strPath) : strCSVPath(strPath)
{
}

UeConfigAsCSV::~UeConfigAsCSV()
{
}

template <class UINT>
UINT ConvertStringToUINT(const std::string &strString)
{
	UINT uiInteger;
	std::istringstream stringstream(strString);
	stringstream >> uiInteger;

	return uiInteger;
}

std::string
ConvertMapToConfigString(std::map<uint16_t, uint16_t> &mapConfig)
{
	uint8_t uiCnt = ZERO;
	std::string strConfig;

	/* Create string for Sx Configuration Pair */
	if (mapConfig.size() != ZERO) {
		for (std::map<uint16_t, uint16_t>::iterator itr = mapConfig.begin();
				itr != mapConfig.end(); itr++) {
			if (ZERO != uiCnt) {
				strConfig += "#";
			}
			
			strConfig += to_string(itr->first);
			strConfig += "-" + to_string(itr->second);
			uiCnt++;
		}
	}

	return strConfig;
}

void
ConvertStringToMap(const std::string &strWord, 
		std::map<uint16_t, uint16_t> &mapConfig)
{
	uint32_t uiWordCntr;
	std::string strPair;
	std::string strConfig;
	uint16_t uiKey, uiValue;
	std::stringstream stream(strWord);

	while (getline(stream, strPair, '#')) {
		uiKey = ZERO;
		uiValue = ZERO;
		uiWordCntr = ZERO;

		std::stringstream streamPair(strPair);
		while (getline(streamPair, strConfig, '-')) {
			switch (uiWordCntr) {

				case KEY:
					uiKey = ConvertStringToUINT<uint16_t>(strConfig);
					break;

				case VALUE:
					uiValue = ConvertStringToUINT<uint16_t>(strConfig);
					break;
			}

			++uiWordCntr;	
		}

		mapConfig.insert({uiKey, uiValue});	
	}	
}

int8_t
UeConfigAsCSV::ReadUeConfig(void)
{
	uint32_t uiWordCntr = ZERO;
	std::string strLine, strWord;
	std::ifstream ifsCpFile(strCSVPath);
	DAdmfApp *ptrInstance = DAdmfApp::GetInstance();

	//std::cout << "Reading confi" << std::endl;
	ELogger::log(LOG_SYSTEM).info("Reading Ue Entries from DB.");
	if (ifsCpFile.is_open()) {
		while (getline(ifsCpFile, strLine)) {
			uiWordCntr = ZERO;
			ue_data_t ueDataTmp;
			std::stringstream stream(strLine);

			while (getline(stream, strWord, ',')) {
				switch (uiWordCntr) {

					case SEQ_ID_ATTR:
						ueDataTmp.uiSeqIdentifier = ConvertStringToUINT<uint64_t>(strWord);
						break;

					case IMSI_ATTR:
						ueDataTmp.uiImsi = ConvertStringToUINT<uint64_t>(strWord);
						break;

					case S11_ATTR:
						ueDataTmp.uiS11 = ConvertStringToUINT<uint16_t>(strWord);
						break;

					case SGW_S5S8_C_ATTR:
						ueDataTmp.uiSgws5s8c = ConvertStringToUINT<uint16_t>(strWord);
						break;

					case PGW_S5S8_C_ATTR:
						ueDataTmp.uiPgws5s8c = ConvertStringToUINT<uint16_t>(strWord);
						break;

					case SX_ATTR:
						ConvertStringToMap(strWord, ueDataTmp.mapSxConfig);
						break;

					case S1U_CONTENT_ATTR:
						ueDataTmp.s1uContent = ConvertStringToUINT<uint16_t>(strWord);
						break;

					case SGW_S5S8U_CONTENT_ATTR:
						ueDataTmp.sgwS5S8Content = ConvertStringToUINT<uint16_t>(strWord);
						break;

					case PGW_S5S8U_CONTENT_ATTR:
						ueDataTmp.pgwS5S8Content = ConvertStringToUINT<uint16_t>(strWord);
						break;

					case SGI_CONTENT_ATTR:
						ueDataTmp.sgiContent = ConvertStringToUINT<uint16_t>(strWord);
						break;

					case INTFC_CONFIG_ATTR:
						ConvertStringToMap(strWord, ueDataTmp.mapIntfcConfig);
						break;

					case FORWARD_ATTR:
						ueDataTmp.uiForward = ConvertStringToUINT<uint16_t>(strWord);
						break;

					case START_TIME_ATTR:
						ueDataTmp.strStartTime = strWord;
						break;

					case STOP_TIME_ATTR:
						ueDataTmp.strStopTime = strWord;
						break;

					case ACK_RCVD_ATTR:
						ueDataTmp.ackReceived = ConvertStringToUINT<uint16_t>(strWord);
						break;

					default:
						break;

				}

				uiWordCntr++;
			}


			int64_t timeToStart = getTimeDiffInMilliSec(ueDataTmp.strStartTime);
			int64_t timeToStop = getTimeDiffInMilliSec(ueDataTmp.strStopTime);
			bool expiredTime = FALSE;

			if ((timeToStart <= ZERO) & (timeToStop <= ZERO)) {

				/* Timer for this imsi has already expired */
				expiredTime = TRUE;
			}

			if ((timeToStart <= ZERO) & (timeToStop > ZERO)) {

				ueDataTmp.iTimeToStart = MILLISECONDS;
				ueDataTmp.iTimeToStop = timeToStop;

			} else {

				ueDataTmp.iTimeToStart = timeToStart;
				ueDataTmp.iTimeToStop = timeToStop;
			}

			if (ueDataTmp.ackReceived == DELETE_ACK ||
				ueDataTmp.ackReceived == STOP_UE_ACK) {

				/* This entry has either been deleted or it has been completed
					acknowledgement for stop request has been received */
				continue;
			}

			if (expiredTime == FALSE) {

				mapUeConfig.insert({ueDataTmp.uiSeqIdentifier, ueDataTmp});

				EUeTimer *startUeTimer = new EUeTimer(ueDataTmp, START_UE);
				//startUeTimer->init(1, 1, NULL, 2000);
				ptrInstance->getTimerThread()->InitTimer(*startUeTimer);

				EUeTimer *stopUeTimer = new EUeTimer(ueDataTmp, STOP_UE);
				//stopUeTimer->init(1, 1, NULL, 2000);
				ptrInstance->getTimerThread()->InitTimer(*stopUeTimer);

				/* Add Ue timer entry in map */
				mapStartUeTimers.insert({ueDataTmp.uiSeqIdentifier, startUeTimer});
				mapStopUeTimers.insert({ueDataTmp.uiSeqIdentifier, stopUeTimer});
			} else {
				mapUeConfig.insert({ueDataTmp.uiSeqIdentifier, ueDataTmp});
			}

			strWord.clear();
			strLine.clear();
		}

		ifsCpFile.close();
		ptrInstance->ReleaseInstance();
		return RET_FAILURE;

	}

	ptrInstance->ReleaseInstance();
	return RET_SUCCESS;
}

int8_t
UeConfigAsCSV::UpdateUeConfig(uint8_t uiAction, ue_data_t &modUeData)
{
	if (ADD_ACTION == uiAction) {
		ELogger::log(LOG_SYSTEM).debug("Adding entry in DB for SequenceIdentifier: "
				"{} and IMSI: {}", modUeData.uiSeqIdentifier, modUeData.uiImsi);
		std::ofstream ofs;

		ofs.open(strCSVPath, std::ios::app);

		ofs << modUeData.uiSeqIdentifier << ","
			<< modUeData.uiImsi << ","
			<< modUeData.uiS11 << ","
			<< modUeData.uiSgws5s8c << ","
			<< modUeData.uiPgws5s8c << ","
			<< ConvertMapToConfigString(modUeData.mapSxConfig) << ","
			<< modUeData.s1uContent << ","
			<< modUeData.sgwS5S8Content << ","
			<< modUeData.pgwS5S8Content << ","
			<< modUeData.sgiContent << ","
			<< ConvertMapToConfigString(modUeData.mapIntfcConfig) << ","
			<< modUeData.uiForward << ","	
			<< modUeData.strStartTime << ","
			<< modUeData.strStopTime << ","
			<< modUeData.ackReceived
			<< std::endl;

		ofs.close();

	} else if (DELETE_ACTION == uiAction) {

		ELogger::log(LOG_SYSTEM).debug("Deleting entry from DB for SequenceId: "
				"{} and IMSI: {}", modUeData.uiSeqIdentifier, modUeData.uiImsi);

		std::string strWord;
		std::string strLine;
		std::ifstream ifs(strCSVPath);
		std::ofstream ofs(UE_TMP_FILE);

		if (ifs.is_open()) {

			while (getline(ifs, strLine)) {

				std::stringstream stream(strLine);

				if (getline(stream, strWord, ',')) {

					if (ConvertStringToUINT<uint64_t>(strWord) != modUeData.uiSeqIdentifier) {

						ofs << strLine << std::endl;

					}
				}
			}

			ifs.close();
		}

		ofs.close();
		remove(strCSVPath.c_str());
		rename(UE_TMP_FILE, strCSVPath.c_str());
	}

	return RET_SUCCESS;
}

