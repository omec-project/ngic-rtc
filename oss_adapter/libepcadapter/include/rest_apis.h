#ifndef __NGIC_REST_APIS_H__
#define __NGIC_REST_APIS_H__

#include "emgmt.h"

#define GET_STAT_URI "/statlive"
#define GET_PERIODIC_TIMER_URI "/periodic_timer"
#define GET_TRANSMIT_TIMER_URI "/transmit_timer"
#define GET_TRANSMIT_COUNT_URI "/transmit_count"
#define GET_REQUEST_TRIES_URI "/request_tries"
#define GET_REQUEST_TIMEOUT_URI "/request_timeout"
#define GET_STAT_LOGGING_URI "/statlogging"
#define GET_PCAP_STATUS_URI "/generate_pcap"
#define GET_STAT_ALL_URI "/statliveall"
#define GET_PERF_FLAG_URI "/perf_flag"
#define GET_RESET_STATS_URI "/reset_stats"
#define GET_STAT_FREQUENCY_URI "/statfreq"
#define GET_CONFIG_LIVE_URI "/configlive"
#define POST_UE_DETAILS_URI "/addueentry"
#define PUT_UE_DETAILS_URI "/updateueentry"
#define DEL_UE_DETAILS_URI "/deleteueentry"
#define RSP_LEN 4096

typedef int (*CRestCallback)(const char *requestBody, char **responseBody);

class RestStateLiveGet : public EManagementHandler
{
	private:
		CRestCallback m_cb;
	public:
		RestStateLiveGet(ELogger &audit);

		void registerHandler();

		virtual Void process(const Pistache::Http::Request& request,
					Pistache::Http::ResponseWriter &response);

		void registerCallback(CRestCallback cb) { m_cb = cb;};
		virtual ~RestStateLiveGet() {}

};

class RestPeriodicTimerGet : public EManagementHandler
{
	private:
		CRestCallback m_cb;
	public:
		RestPeriodicTimerGet(ELogger &audit);

		void registerHandler();

		virtual Void process(const Pistache::Http::Request& request,
					Pistache::Http::ResponseWriter &response);

		void registerCallback(CRestCallback cb) { m_cb = cb;};
		virtual ~RestPeriodicTimerGet() {}

};

class RestTransmitTimerGet : public EManagementHandler
{
	private:
		CRestCallback m_cb;
	public:
		RestTransmitTimerGet(ELogger &audit);

		void registerHandler();

		virtual Void process(const Pistache::Http::Request& request,
					Pistache::Http::ResponseWriter &response);

		void registerCallback(CRestCallback cb) { m_cb = cb;};
		virtual ~RestTransmitTimerGet() {}

};

class RestTransmitCountGet : public EManagementHandler
{
	private:
		CRestCallback m_cb;
	public:
		RestTransmitCountGet(ELogger &audit);

		void registerHandler();

		virtual Void process(const Pistache::Http::Request& request,
					Pistache::Http::ResponseWriter &response);

		void registerCallback(CRestCallback cb) { m_cb = cb;};
		virtual ~RestTransmitCountGet() {}

};

class RestRequestTriesGet : public EManagementHandler
{
	private:
		CRestCallback m_cb;
	public:
		RestRequestTriesGet(ELogger &audit);

		void registerHandler();

		virtual Void process(const Pistache::Http::Request& request,
					Pistache::Http::ResponseWriter &response);

		void registerCallback(CRestCallback cb) { m_cb = cb;};
		virtual ~RestRequestTriesGet() {}

};

class RestRequestTimeoutGet : public EManagementHandler
{
	private:
		CRestCallback m_cb;
	public:
		RestRequestTimeoutGet(ELogger &audit);

		void registerHandler();

		virtual Void process(const Pistache::Http::Request& request,
					Pistache::Http::ResponseWriter &response);

		void registerCallback(CRestCallback cb) { m_cb = cb;};
		virtual ~RestRequestTimeoutGet() {}

};

class RestStatLoggingGet : public EManagementHandler
{
	private:
		CRestCallback m_cb;
	public:
		RestStatLoggingGet(ELogger &audit);

		void registerHandler();

		virtual Void process(const Pistache::Http::Request& request,
					Pistache::Http::ResponseWriter &response);

		void registerCallback(CRestCallback cb) { m_cb = cb;};
		virtual ~RestStatLoggingGet() {}

};

class RestPcapStatusGet : public EManagementHandler
{
	private:
		CRestCallback m_cb;
	public:
		RestPcapStatusGet(ELogger &audit);

		void registerHandler();

		virtual Void process(const Pistache::Http::Request& request,
					Pistache::Http::ResponseWriter &response);

		void registerCallback(CRestCallback cb) { m_cb = cb;};
		virtual ~RestPcapStatusGet() {}

};

class RestConfigurationGet : public EManagementHandler
{
	private:
		CRestCallback m_cb;
	public:
		RestConfigurationGet(ELogger &audit);

		void registerHandler();

		virtual Void process(const Pistache::Http::Request& request,
					Pistache::Http::ResponseWriter &response);

		void registerCallback(CRestCallback cb) { m_cb = cb;};
		virtual ~RestConfigurationGet() {}

};

class RestStatLiveAllGet : public EManagementHandler
{
	private:
		CRestCallback m_cb;
	public:
		RestStatLiveAllGet(ELogger &audit);

		void registerHandler();

		virtual Void process(const Pistache::Http::Request& request,
					Pistache::Http::ResponseWriter &response);

		void registerCallback(CRestCallback cb) { m_cb = cb;};
		virtual ~RestStatLiveAllGet() {}

};

class RestStatFrequencyGet : public EManagementHandler
{
	private:
		CRestCallback m_cb;
	public:
		RestStatFrequencyGet(ELogger &audit);

		void registerHandler();

		virtual Void process(const Pistache::Http::Request& request,
					Pistache::Http::ResponseWriter &response);

		void registerCallback(CRestCallback cb) { m_cb = cb;};
		virtual ~RestStatFrequencyGet() {}

};

class RestPerfFlagGet : public EManagementHandler
{
	private:
		CRestCallback m_cb;
	public:
		RestPerfFlagGet(ELogger &audit);

		void registerHandler();

		virtual Void process(const Pistache::Http::Request& request,
					Pistache::Http::ResponseWriter &response);

		void registerCallback(CRestCallback cb) { m_cb = cb;};
		virtual ~RestPerfFlagGet() {}

};

class RestPeriodicTimerPost : public EManagementHandler
{
	private:
		CRestCallback m_cb;
	public:
		RestPeriodicTimerPost(ELogger &audit);

		void registerHandler();

		virtual Void process(const Pistache::Http::Request& request,
					Pistache::Http::ResponseWriter &response);

		void registerCallback(CRestCallback cb) { m_cb = cb;};
		virtual ~RestPeriodicTimerPost() {}

};

class RestTransmitTimerPost : public EManagementHandler
{
	private:
		CRestCallback m_cb;
	public:
		RestTransmitTimerPost(ELogger &audit);

		void registerHandler();

		virtual Void process(const Pistache::Http::Request& request,
					Pistache::Http::ResponseWriter &response);

		void registerCallback(CRestCallback cb) { m_cb = cb;};
		virtual ~RestTransmitTimerPost() {}

};

class RestTransmitCountPost : public EManagementHandler
{
	private:
		CRestCallback m_cb;
	public:
		RestTransmitCountPost(ELogger &audit);

		void registerHandler();

		virtual Void process(const Pistache::Http::Request& request,
					Pistache::Http::ResponseWriter &response);

		void registerCallback(CRestCallback cb) { m_cb = cb;};
		virtual ~RestTransmitCountPost() {}

};

class RestRequestTriesPost : public EManagementHandler
{
	private:
		CRestCallback m_cb;
	public:
		RestRequestTriesPost(ELogger &audit);

		void registerHandler();

		virtual Void process(const Pistache::Http::Request& request,
					Pistache::Http::ResponseWriter &response);

		void registerCallback(CRestCallback cb) { m_cb = cb;};
		virtual ~RestRequestTriesPost() {}

};

class RestRequestTimeoutPost : public EManagementHandler
{
	private:
		CRestCallback m_cb;
	public:
		RestRequestTimeoutPost(ELogger &audit);

		void registerHandler();

		virtual Void process(const Pistache::Http::Request& request,
					Pistache::Http::ResponseWriter &response);

		void registerCallback(CRestCallback cb) { m_cb = cb;};
		virtual ~RestRequestTimeoutPost() {}

};

class RestStatLoggingPost : public EManagementHandler
{
	private:
		CRestCallback m_cb;
	public:
		RestStatLoggingPost(ELogger &audit);

		void registerHandler();

		virtual Void process(const Pistache::Http::Request& request,
					Pistache::Http::ResponseWriter &response);

		void registerCallback(CRestCallback cb) { m_cb = cb;};
		virtual ~RestStatLoggingPost() {}

};

class RestPcapStatusPost : public EManagementHandler
{
	private:
		CRestCallback m_cb;
	public:
		RestPcapStatusPost(ELogger &audit);

		void registerHandler();

		virtual Void process(const Pistache::Http::Request& request,
					Pistache::Http::ResponseWriter &response);

		void registerCallback(CRestCallback cb) { m_cb = cb;};
		virtual ~RestPcapStatusPost() {}

};

class RestResetStatPost : public EManagementHandler
{
	private:
		CRestCallback m_cb;
	public:
		RestResetStatPost(ELogger &audit);

		void registerHandler();

		virtual Void process(const Pistache::Http::Request& request,
					Pistache::Http::ResponseWriter &response);

		void registerCallback(CRestCallback cb) { m_cb = cb;};
		virtual ~RestResetStatPost() {}

};

class RestStatFrequencyPost : public EManagementHandler
{
	private:
		CRestCallback m_cb;
	public:
		RestStatFrequencyPost(ELogger &audit);

		void registerHandler();

		virtual Void process(const Pistache::Http::Request& request,
					Pistache::Http::ResponseWriter &response);

		void registerCallback(CRestCallback cb) { m_cb = cb;};
		virtual ~RestStatFrequencyPost() {}

};

class RestPerfFlagPost : public EManagementHandler
{
	private:
		CRestCallback m_cb;
	public:
		RestPerfFlagPost(ELogger &audit);

		void registerHandler();

		virtual Void process(const Pistache::Http::Request& request,
					Pistache::Http::ResponseWriter &response);

		void registerCallback(CRestCallback cb) { m_cb = cb;};
		virtual ~RestPerfFlagPost() {}

};

class RestUEDetailsPost : public EManagementHandler
{
	private:
		CRestCallback m_cb;
	public:
		RestUEDetailsPost(ELogger &audit);

		void registerHandler();

		virtual Void process(const Pistache::Http::Request& request,
					Pistache::Http::ResponseWriter &response);

		void registerCallback(CRestCallback cb) { m_cb = cb;};
		virtual ~RestUEDetailsPost() {}

};

class RestUEDetailsPut : public EManagementHandler
{
	private:
		CRestCallback m_cb;
	public:
		RestUEDetailsPut(ELogger &audit);

		void registerHandler();

		virtual Void process(const Pistache::Http::Request& request,
					Pistache::Http::ResponseWriter &response);

		void registerCallback(CRestCallback cb) { m_cb = cb;};
		virtual ~RestUEDetailsPut() {}

};

class RestUEDetailsDel : public EManagementHandler
{
	private:
		CRestCallback m_cb;
	public:
		RestUEDetailsDel(ELogger &audit);

		void registerHandler();

		virtual Void process(const Pistache::Http::Request& request,
					Pistache::Http::ResponseWriter &response);

		void registerCallback(CRestCallback cb) { m_cb = cb;};
		virtual ~RestUEDetailsDel() {}

};

#endif /* __NGIC_REST_APIS_H__ */
