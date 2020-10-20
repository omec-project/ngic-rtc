
#include "rest_apis.h"


RestStateLiveGet::RestStateLiveGet(ELogger &audit)
: EManagementHandler(EManagementHandler::HttpMethod::httpGet,
			GET_STAT_URI, audit)
{}

void
RestStateLiveGet::process(const Pistache::Http::Request& request,
				Pistache::Http::ResponseWriter &response)
{
	char *res = (char *)malloc(RSP_LEN);
	m_cb(request.body().c_str(), &res);
	response.send(Pistache::Http::Code::Ok, res);
	free(res);
}

RestPeriodicTimerGet::RestPeriodicTimerGet(ELogger &audit)
: EManagementHandler(EManagementHandler::HttpMethod::httpGet,
			GET_PERIODIC_TIMER_URI, audit)
{}

void
RestPeriodicTimerGet::process(const Pistache::Http::Request& request,
				Pistache::Http::ResponseWriter &response)
{
	char *res = (char *)malloc(RSP_LEN);
	m_cb(request.body().c_str(), &res);
	response.send(Pistache::Http::Code::Ok, res);
	free(res);
}

RestTransmitTimerGet::RestTransmitTimerGet(ELogger &audit)
: EManagementHandler(EManagementHandler::HttpMethod::httpGet,
			GET_TRANSMIT_TIMER_URI, audit)
{}

void
RestTransmitTimerGet::process(const Pistache::Http::Request& request,
				Pistache::Http::ResponseWriter &response)
{
	char *res = (char *)malloc(RSP_LEN);
	m_cb(request.body().c_str(), &res);
	response.send(Pistache::Http::Code::Ok, res);
	free(res);
}

RestTransmitCountGet::RestTransmitCountGet(ELogger &audit)
: EManagementHandler(EManagementHandler::HttpMethod::httpGet,
			GET_TRANSMIT_COUNT_URI, audit)
{}

void
RestTransmitCountGet::process(const Pistache::Http::Request& request,
				Pistache::Http::ResponseWriter &response)
{
	char *res = (char *)malloc(RSP_LEN);
	m_cb(request.body().c_str(), &res);
	response.send(Pistache::Http::Code::Ok, res);
	free(res);
}

RestRequestTriesGet::RestRequestTriesGet(ELogger &audit)
: EManagementHandler(EManagementHandler::HttpMethod::httpGet,
			GET_REQUEST_TRIES_URI, audit)
{}

void
RestRequestTriesGet::process(const Pistache::Http::Request& request,
				Pistache::Http::ResponseWriter &response)
{
	char *res = (char *)malloc(RSP_LEN);
	m_cb(request.body().c_str(), &res);
	response.send(Pistache::Http::Code::Ok, res);
	free(res);
}

RestRequestTimeoutGet::RestRequestTimeoutGet(ELogger &audit)
: EManagementHandler(EManagementHandler::HttpMethod::httpGet,
			GET_REQUEST_TIMEOUT_URI, audit)
{}

void
RestRequestTimeoutGet::process(const Pistache::Http::Request& request,
				Pistache::Http::ResponseWriter &response)
{
	char *res = (char *)malloc(RSP_LEN);
	m_cb(request.body().c_str(), &res);
	response.send(Pistache::Http::Code::Ok, res);
	free(res);
}

RestPcapStatusGet::RestPcapStatusGet(ELogger &audit)
: EManagementHandler(EManagementHandler::HttpMethod::httpGet,
			GET_PCAP_STATUS_URI, audit)
{}

void
RestPcapStatusGet::process(const Pistache::Http::Request& request,
				Pistache::Http::ResponseWriter &response)
{
	char *res = (char *)malloc(RSP_LEN);
	m_cb(request.body().c_str(), &res);
	response.send(Pistache::Http::Code::Ok, res);
	free(res);
}

RestStatLoggingGet::RestStatLoggingGet(ELogger &audit)
: EManagementHandler(EManagementHandler::HttpMethod::httpGet,
			GET_STAT_LOGGING_URI, audit)
{}

void
RestStatLoggingGet::process(const Pistache::Http::Request& request,
				Pistache::Http::ResponseWriter &response)
{
	char *res = (char *)malloc(RSP_LEN);
	m_cb(request.body().c_str(), &res);
	response.send(Pistache::Http::Code::Ok, res);
	free(res);
}

RestConfigurationGet::RestConfigurationGet(ELogger &audit)
: EManagementHandler(EManagementHandler::HttpMethod::httpGet,
			GET_CONFIG_LIVE_URI, audit)
{}

void
RestConfigurationGet::process(const Pistache::Http::Request& request,
				Pistache::Http::ResponseWriter &response)
{
	char *res = (char *)malloc(RSP_LEN);
	m_cb(request.body().c_str(), &res);
	response.send(Pistache::Http::Code::Ok, res);
	free(res);
}

RestStatLiveAllGet::RestStatLiveAllGet(ELogger &audit)
: EManagementHandler(EManagementHandler::HttpMethod::httpGet,
			GET_STAT_ALL_URI, audit)
{}

void
RestStatLiveAllGet::process(const Pistache::Http::Request& request,
				Pistache::Http::ResponseWriter &response)
{
	char *res = (char *)malloc(RSP_LEN);
	m_cb(request.body().c_str(), &res);
	response.send(Pistache::Http::Code::Ok, res);
	free(res);
}

RestStatFrequencyGet::RestStatFrequencyGet(ELogger &audit)
: EManagementHandler(EManagementHandler::HttpMethod::httpGet,
			GET_STAT_FREQUENCY_URI, audit)
{}

void
RestStatFrequencyGet::process(const Pistache::Http::Request& request,
				Pistache::Http::ResponseWriter &response)
{
	char *res = (char *)malloc(RSP_LEN);
	m_cb(request.body().c_str(), &res);
	response.send(Pistache::Http::Code::Ok, res);
	free(res);
}

RestPeriodicTimerPost::RestPeriodicTimerPost(ELogger &audit)
: EManagementHandler(EManagementHandler::HttpMethod::httpPost,
			GET_PERIODIC_TIMER_URI, audit)
{}

void
RestPeriodicTimerPost::process(const Pistache::Http::Request& request,
				Pistache::Http::ResponseWriter &response)
{
	char *res = (char *)malloc(RSP_LEN);
	m_cb(request.body().c_str(), &res);
	response.send(Pistache::Http::Code::Ok, res);
	free(res);
}

RestTransmitTimerPost::RestTransmitTimerPost(ELogger &audit)
: EManagementHandler(EManagementHandler::HttpMethod::httpPost,
			GET_TRANSMIT_TIMER_URI, audit)
{}

void
RestTransmitTimerPost::process(const Pistache::Http::Request& request,
				Pistache::Http::ResponseWriter &response)
{
	char *res = (char *)malloc(RSP_LEN);
	m_cb(request.body().c_str(), &res);
	response.send(Pistache::Http::Code::Ok, res);
	free(res);
}

RestTransmitCountPost::RestTransmitCountPost(ELogger &audit)
: EManagementHandler(EManagementHandler::HttpMethod::httpPost,
			GET_TRANSMIT_COUNT_URI, audit)
{}

void
RestTransmitCountPost::process(const Pistache::Http::Request& request,
				Pistache::Http::ResponseWriter &response)
{
	char *res = (char *)malloc(RSP_LEN);
	m_cb(request.body().c_str(), &res);
	response.send(Pistache::Http::Code::Ok, res);
	free(res);
}

RestRequestTriesPost::RestRequestTriesPost(ELogger &audit)
: EManagementHandler(EManagementHandler::HttpMethod::httpPost,
			GET_REQUEST_TRIES_URI, audit)
{}

void
RestRequestTriesPost::process(const Pistache::Http::Request& request,
				Pistache::Http::ResponseWriter &response)
{
	char *res = (char *)malloc(RSP_LEN);
	m_cb(request.body().c_str(), &res);
	response.send(Pistache::Http::Code::Ok, res);
	free(res);
}

RestRequestTimeoutPost::RestRequestTimeoutPost(ELogger &audit)
: EManagementHandler(EManagementHandler::HttpMethod::httpPost,
			GET_REQUEST_TIMEOUT_URI, audit)
{}

void
RestRequestTimeoutPost::process(const Pistache::Http::Request& request,
				Pistache::Http::ResponseWriter &response)
{
	char *res = (char *)malloc(RSP_LEN);
	m_cb(request.body().c_str(), &res);
	response.send(Pistache::Http::Code::Ok, res);
	free(res);
}

RestPcapStatusPost::RestPcapStatusPost(ELogger &audit)
: EManagementHandler(EManagementHandler::HttpMethod::httpPost,
			GET_PCAP_STATUS_URI, audit)
{}

void
RestPcapStatusPost::process(const Pistache::Http::Request& request,
				Pistache::Http::ResponseWriter &response)
{
	char *res = (char *)malloc(RSP_LEN);
	m_cb(request.body().c_str(), &res);
	response.send(Pistache::Http::Code::Ok, res);
	free(res);
}

RestStatLoggingPost::RestStatLoggingPost(ELogger &audit)
: EManagementHandler(EManagementHandler::HttpMethod::httpPost,
			GET_STAT_LOGGING_URI, audit)
{}

void
RestStatLoggingPost::process(const Pistache::Http::Request& request,
				Pistache::Http::ResponseWriter &response)
{
	char *res = (char *)malloc(RSP_LEN);
	m_cb(request.body().c_str(), &res);
	response.send(Pistache::Http::Code::Ok, res);
	free(res);
}

RestResetStatPost::RestResetStatPost(ELogger &audit)
: EManagementHandler(EManagementHandler::HttpMethod::httpPost,
			GET_RESET_STATS_URI, audit)
{}

void
RestResetStatPost::process(const Pistache::Http::Request& request,
				Pistache::Http::ResponseWriter &response)
{
	char *res = (char *)malloc(RSP_LEN);
	m_cb(request.body().c_str(), &res);
	response.send(Pistache::Http::Code::Ok, res);
	free(res);
}

RestStatFrequencyPost::RestStatFrequencyPost(ELogger &audit)
: EManagementHandler(EManagementHandler::HttpMethod::httpPost,
			GET_STAT_FREQUENCY_URI, audit)
{}

void
RestStatFrequencyPost::process(const Pistache::Http::Request& request,
				Pistache::Http::ResponseWriter &response)
{
	char *res = (char *)malloc(RSP_LEN);
	m_cb(request.body().c_str(), &res);
	response.send(Pistache::Http::Code::Ok, res);
	free(res);
}

RestUEDetailsPost::RestUEDetailsPost(ELogger &audit)
: EManagementHandler(EManagementHandler::HttpMethod::httpPost,
			POST_UE_DETAILS_URI, audit)
{}

void
RestUEDetailsPost::process(const Pistache::Http::Request& request,
				Pistache::Http::ResponseWriter &response)
{
	char *res = (char *)malloc(RSP_LEN);
	m_cb(request.body().c_str(), &res);
	response.send(Pistache::Http::Code::Ok, res);
	free(res);
}

RestUEDetailsPut::RestUEDetailsPut(ELogger &audit)
: EManagementHandler(EManagementHandler::HttpMethod::httpPost,
			PUT_UE_DETAILS_URI, audit)
{}

void
RestUEDetailsPut::process(const Pistache::Http::Request& request,
				Pistache::Http::ResponseWriter &response)
{
	char *res = (char *)malloc(RSP_LEN);
	m_cb(request.body().c_str(), &res);
	response.send(Pistache::Http::Code::Ok, res);
	free(res);
}

RestUEDetailsDel::RestUEDetailsDel(ELogger &audit)
: EManagementHandler(EManagementHandler::HttpMethod::httpPost,
			DEL_UE_DETAILS_URI, audit)
{}

void
RestUEDetailsDel::process(const Pistache::Http::Request& request,
				Pistache::Http::ResponseWriter &response)
{
	char *res = (char *)malloc(RSP_LEN);
	m_cb(request.body().c_str(), &res);
	response.send(Pistache::Http::Code::Ok, res);
	free(res);
}
