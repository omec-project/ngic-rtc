/*
 * Copyright (c) 2019 Sprint
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


#ifndef __CSTATS_DEV_H
#define __CSTATS_DEV_H

using namespace std;

enum cp_config {
    SGWC = 1,
    PGWC,
    SAEGWC
};


class CStatMessages
{
    string nodestr;
	bool suppress;
public:
    CStatMessages(bool suppressed)
    {
        nodestr = "messages";
		suppress = suppressed;
    }

    string getNodeName()
    {
        return nodestr;
    }

    void serialize(const SPeer* peer,
        statsrapidjson::Value& row,
        statsrapidjson::Value& arrayObjects,
        statsrapidjson::Document::AllocatorType& allocator);

    void serializeS11(const SPeer* peer,
        statsrapidjson::Value& row,
        statsrapidjson::Value& arrayObjects,
        statsrapidjson::Document::AllocatorType& allocator);

    void serializeS5S8(const SPeer* peer,
        statsrapidjson::Value& row,
        statsrapidjson::Value& arrayObjects,
        statsrapidjson::Document::AllocatorType& allocator);

    void serializeSx(const SPeer* peer,
        statsrapidjson::Value& row,
        statsrapidjson::Value& arrayObjects,
        statsrapidjson::Document::AllocatorType& allocator);

    void serializeGx(const SPeer* peer,
        statsrapidjson::Value& row,
        statsrapidjson::Value& arrayObjects,
        statsrapidjson::Document::AllocatorType& allocator);

 	void serializeSystem(const cli_node_t *cli_node,
    	statsrapidjson::Value& row,
    	statsrapidjson::Value& arrayObjects,
    	statsrapidjson::Document::AllocatorType& allocator);

private:
};

class CStatHealth
{
    string nodestr;
	bool suppress;
public:
    CStatHealth(bool suppressed)
    {
        nodestr = "health";
		suppress = suppressed;
    }

    string getNodeName()
    {
        return nodestr;
    }

    void serialize(const SPeer* peer,
        statsrapidjson::Value& row,
        statsrapidjson::Value& arrayObjects,
        statsrapidjson::Document::AllocatorType& allocator);

private:
};

class CStatPeers
{
    string nodestr;
	bool suppress;

public:
    CStatPeers(bool suppressed)
    {
        nodestr = "peers";
		suppress = suppressed;
    }

    string getNodeName()
    {
        return nodestr;
    }

    void serialize(const SPeer* peer,
        statsrapidjson::Value& row,
        statsrapidjson::Value& arrayObjects,
        statsrapidjson::Document::AllocatorType& allocator);

private:
};

class CStatInterfaces
{
    string nodestr;
    CStatPeers peer;
	bool suppress;
public:
    CStatInterfaces(bool suppressed) : peer(suppressed)
    {
        nodestr = "interfaces";
		suppress = suppressed;
    }

    string getNodeName()
    {
        return nodestr;
    }

    void serialize(cli_node_t *cli_node,
        statsrapidjson::Value& row,
        statsrapidjson::Value& arrayObjects,
        statsrapidjson::Document::AllocatorType& allocator);

    void serializeInterface(cli_node_t *cli_node,
        statsrapidjson::Value& row,
        statsrapidjson::Value& arrayObjects,
        statsrapidjson::Document::AllocatorType& allocator,EInterfaceType it);

private:
};

class CStatGateway
{
    string nodestr;
	EString reportTimeStr;
    CStatInterfaces interfaces;
	bool suppress;
public:
    CStatGateway(bool suppressed) : interfaces(suppressed)
    {
        nodestr = "gateway";
		suppress = suppressed;
    }

    string getNodeName()
    {
        return nodestr;
    }

	 void initInterfaceDirection(cp_config gatway);

    void serialize(cli_node_t *cli_node,
        statsrapidjson::Value& row,
        statsrapidjson::Value& arrayObjects,
        statsrapidjson::Document::AllocatorType& allocator);

private:
};

class CStatSystem
{
    string nodestr;
	bool suppress;
public:
    CStatSystem(bool suppressed)
    {
        nodestr = "system";
		suppress = suppressed;
    }

    string getNodeName()
    {
        return nodestr;
    }

    void serialize(cli_node_t *cli_node,
        statsrapidjson::Value& row,
        statsrapidjson::Value& arrayObjects,
        statsrapidjson::Document::AllocatorType& allocator);

private:
};

class CStatSession
{
    string nodestr;
	bool suppress;
public:
    CStatSession(bool suppressed)
    {
        nodestr = "sessions";
		suppress = suppressed;
    }

    string getNodeName()
    {
        return nodestr;
    }

    void serialize(cli_node_t *cli_node,
        statsrapidjson::Value& row,
        statsrapidjson::Value& arrayObjects,
        statsrapidjson::Document::AllocatorType& allocator);

private:
};

#endif /* __CSTATS_DEV_H */

