/* 
 * Copyright (C) 2015 Raffael Holz aka LeGone - All Rights Reserved
 * http://www.legone.name
 *
 * You may use, distribute and modify this code under the
 * terms of the MIT license.
 *
 * Based on the SDK-Sample-Plugin.
 */


#ifdef _WIN32
#pragma warning (disable : 4100)  /* Disable Unreferenced parameter warning */
#include <Windows.h>
#endif

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <assert.h>
#include <iostream>
#include "public_errors.h"
#include "public_errors_rare.h"
#include "public_definitions.h"
#include "public_rare_definitions.h"
#include "ts3_functions.h"
#include "plugin.h"
#include "dlib/threads.h"
#include "dlib/misc_api.h"  // for dlib::sleep
#include "dlib/gui_widgets.h"
#include <dlib/iosockstream.h>
#include <iostream>

using namespace dlib;

static struct TS3Functions ts3Functions;

#ifdef _WIN32
#define _strcpy(dest, destSize, src) strcpy_s(dest, destSize, src)
#define snprintf sprintf_s
#else
#define _strcpy(dest, destSize, src) { strncpy(dest, src, destSize-1); (dest)[destSize-1] = '\0'; }
#endif

#define PLUGIN_API_VERSION 20

#define PATH_BUFSIZE 512
#define COMMAND_BUFSIZE 128
#define INFODATA_BUFSIZE 128
#define SERVERINFO_BUFSIZE 256
#define CHANNELINFO_BUFSIZE 512
#define RETURNCODE_BUFSIZE 128
#define PLUGIN_THREAD_TIMEOUT 250

static char* pluginID = NULL;

static bool bCheckPings = true;
static bool bActive = true;
unsigned long maxPing = 100;

#ifdef _WIN32
static int wcharToUtf8(const wchar_t* str, char** result) {
	int outlen = WideCharToMultiByte(CP_UTF8, 0, str, -1, 0, 0, 0, 0);
	*result = (char*)malloc(outlen);
	if(WideCharToMultiByte(CP_UTF8, 0, str, -1, *result, outlen, 0, 0) == 0) {
		*result = NULL;
		return -1;
	}
	return 0;
}
#endif

int ts3plugin_requestAutoload()
{
	return 1;
}

int ts3plugin_onServerErrorEvent(::uint64 serverConnectionHandlerID, const char* errorMessage, unsigned int error, const char* returnCode, const char* extraMessage)
{
	return 1;
}

/*********************************** Required functions ************************************/

const char* ts3plugin_name() {
#ifdef _WIN32
	static char* result = NULL;
	if(!result)
	{
		const wchar_t* name = L"Anti-Proxy-Plugin";
		if(wcharToUtf8(name, &result) == -1)
		{
			result = "Anti-Proxy-Plugin";
		}
	}
	return result;
#else
	return "Anti-Proxy-Plugin";
#endif
}

const char* ts3plugin_version()
{
    return "1.0";
}

int ts3plugin_apiVersion()
{
	return PLUGIN_API_VERSION;
}

const char* ts3plugin_author()
{
    return "Raffael Holz | LeGone | legone.name";
}

const char* ts3plugin_description()
{
    return "Anti-Proxy-Plugin";
}

void ts3plugin_setFunctionPointers(const struct TS3Functions funcs)
{
    ts3Functions = funcs;
}

std::string GetCountryCode(std::string ip)
{
	try
	{
		dlib::iosockstream stream("www.legone.name:80");

		stream << "GET /location/iptocountrycode.php?ip=" << ip << " HTTP/1.0\r\nHost: www.legone.name:80\r\n\r\n";

		std::string completeFileAsString;
		while (stream.peek() != EOF)
		{
			completeFileAsString += (unsigned char)stream.get();
		}
		
		size_t posOfHeaderEnd = completeFileAsString.find("c:->");
		if (posOfHeaderEnd != std::string::npos)
		{
			// Erase the \r\n\r\n chars
			posOfHeaderEnd += 4;

			completeFileAsString = &completeFileAsString[posOfHeaderEnd];

			return (completeFileAsString);
		}
	}
	catch (...)
	{
		// Just ignore the exception
	}

	return ("");
}

unsigned char gPingChecks[500];
void ts3plugin_checkPings()
{
	unsigned int error;
	char* str;
	anyID* clients;
	anyID* client;
	anyID result;
	dlib::uint64 ping = 0;
	dlib::uint64 serverConnectionHandlerID = ts3Functions.getCurrentServerConnectionHandlerID();
	anyID myID;

	/* Get own clientID */
	if (ts3Functions.getClientID(serverConnectionHandlerID, &myID) != ERROR_ok)
	{
		ts3Functions.logMessage("Error querying client ID", LogLevel_ERROR, "Plugin", serverConnectionHandlerID);
	}

	if ((error = ts3Functions.getClientList(serverConnectionHandlerID, &clients)) != ERROR_ok)
	{
		char* errorMsg;
		if(ts3Functions.getErrorMessage(error, &errorMsg) == ERROR_ok)
		{
			ts3Functions.logMessage("Error retrieving list of clients:", LogLevel_WARNING, "Anti-Proxy-Plugin", 0);
			ts3Functions.logMessage(errorMsg, LogLevel_WARNING, "Anti-Proxy-Plugin", 0);
			ts3Functions.freeMemory(errorMsg);
		}

		return;
	}

	/*
	if (ts3Functions.requestConnectionInfo(serverConnectionHandlerID, myID, NULL) == ERROR_ok)
	{
		if (ts3Functions.getConnectionVariableAsUInt64(serverConnectionHandlerID, myID, CONNECTION_PING, &ping) == ERROR_ok) 
		{
			if (ping > maxPing)
			{
				return;
			}
		}
	}
	*/

	// Find the first client that matches the criteria
	for (client = clients, result = (anyID)NULL; *client != (dlib::uint64)NULL && result == (anyID)NULL; client++)
	{
		if ((anyID)*client != myID)
		{
			if (ts3Functions.requestConnectionInfo(serverConnectionHandlerID, (anyID)*client, NULL) == ERROR_ok) 
			{
				char *ip;
				if (ts3Functions.getConnectionVariableAsString(serverConnectionHandlerID, (anyID)*client, CONNECTION_CLIENT_IP, &ip) == ERROR_ok) 
				{
					std::string country = dlib::tolower(GetCountryCode(ip));

					if (country != "" && country != "de" && country != "ch" && country != "at")
					{
						ts3Functions.requestClientKickFromServer(serverConnectionHandlerID, (anyID)*client, "You shall not enter our world!", str);
					}
					
					ts3Functions.freeMemory(ip);
				}

				if (ts3Functions.getConnectionVariableAsUInt64(serverConnectionHandlerID, (anyID)*client, CONNECTION_PING, &ping) == ERROR_ok) 
				{
					if (ping > maxPing)
					{
						 if (gPingChecks[(anyID)*client] > 20)
							 ts3Functions.requestClientKickFromServer(serverConnectionHandlerID, (anyID)*client, ("YOUR [b]" + dlib::cast_to_string(ping) + "[/b] PING IS TOO HIGH!").c_str(), str);
						// else
						//if (gPingChecks[(anyID)*client] > 5)
							//ts3Functions.requestSendPrivateTextMsg(serverConnectionHandlerID, ("YOUR PING [b]" + dlib::cast_to_string(ping) + "[/b] IS TOO HIGH! PROXYSERVERS ARE NOT ALLOWED!").c_str(), (anyID)*client, str);
						
						++gPingChecks[(anyID)*client];

					}
					else
					{
						gPingChecks[(anyID)*client] = 0;
					}
				}
			}
		}
	}
	
	ts3Functions.freeMemory(clients);
}

void ts3plugin_thread_checkpings(void*)
{
	while (bCheckPings)
	{
		Sleep(500);
		if (bActive)
			ts3plugin_checkPings();
	}
}


int ts3plugin_init()
{
    char appPath[PATH_BUFSIZE];
    char resourcesPath[PATH_BUFSIZE];
    char configPath[PATH_BUFSIZE];
	char pluginPath[PATH_BUFSIZE];

    printf("PLUGIN: init\n");

    ts3Functions.getAppPath(appPath, PATH_BUFSIZE);
    ts3Functions.getResourcesPath(resourcesPath, PATH_BUFSIZE);
    ts3Functions.getConfigPath(configPath, PATH_BUFSIZE);
	ts3Functions.getPluginPath(pluginPath, PATH_BUFSIZE);

	printf("PLUGIN: App path: %s\nResources path: %s\nConfig path: %s\nPlugin path: %s\n", appPath, resourcesPath, configPath, pluginPath);

	ts3Functions.logMessage("Starting Pingcheck-Thread", LogLevel_INFO, "Anti-Proxy-Plugin", 0);
	dlib::create_new_thread(ts3plugin_thread_checkpings, 0);

    return 0;
}

void ts3plugin_shutdown()
{
    printf("PLUGIN: shutdown\n");

	bCheckPings = false;
	Sleep(500);

	if(pluginID) {
		free(pluginID);
		pluginID = NULL;
	}
}

//  ----------------------------------------------------------------------------

class win : public drawable_window 
{
    /*
        Here I am going to define our window.  In general, you can define as 
        many window types as you like and make as many instances of them as you want.
        In this example I am only making one though.
    */
public:
    win() : // All widgets take their parent window as an argument to their constructor.
        c(*this),
        up(*this),
		down(*this),
        mbar(*this)
    {
        // tell our button to put itself at the position (10,60). 
        down.set_pos(0,30);
        down.set_name("Lower");

		up.set_pos(down.left() + down.width() + 5, 30);
        up.set_name("Higher");

        // lets put the label 5 pixels below the button
        c.set_pos(down.left(),down.bottom() + 5);

        // set which function should get called when the button gets clicked.  In this case we want
        // the on_button_clicked member to be called on *this.
        up.set_click_handler(*this,&win::on_button_up_clicked);
		down.set_click_handler(*this,&win::on_button_down_clicked);
        // Alternatively, if you have a compiler which supports the lambda functions from the
        // new C++ standard then you can use a lambda function instead of telling the click
        // handler to call one of the member functions.  So for example, you could do this
        // instead (uncomment the code if you have C++0x support):
        /*
        b.set_click_handler([&](){
                ++counter;
                ostringstream sout;
                sout << "Counter: " << counter;
                c.set_text(sout.str());
                });
        */
        // In general, all the functions which register events can take either member 
        // functions or lambda functions.

        
        // Lets also make a simple menu bar.  
        // First we say how many menus we want in our menu bar.  In this example we only want 1.
        mbar.set_number_of_menus(1);
        // Now we set the name of our menu.  The 'M' means that the M in Menu will be underlined
        // and the user will be able to select it by hitting alt+M
        mbar.set_menu_name(0,"Menu",'M');

        // Now we add some items to the menu.  Note that items in a menu are listed in the
        // order in which they were added.

        //mbar.menu(0).add_menu_item(menu_item_separator());
        // Now lets make a menu item that calls show_about when the user selects it.  
        mbar.menu(0).add_menu_item(menu_item_text("About",*this,&win::show_about,'A'));


        // set the size of this window
        set_size(170, 80);

		refreshPing();

        set_title("Anti-Proxy-Plugin");
        show();
    } 

    ~win()
    {
        // You should always call close_window() in the destructor of window
        // objects to ensure that no events will be sent to this window while 
        // it is being destructed.  
        close_window();
    }

private:

    void on_button_up_clicked()
    {
        maxPing += 5;
        refreshPing();
    }

    void on_button_down_clicked()
    {
        maxPing -= 5;
        refreshPing();
    }

    void refreshPing()
    {
        std::ostringstream sout;
        sout << "Kick if ping higher than: " << maxPing;
        c.set_text(sout.str());
    }

    void show_about()
    {
        message_box("About","By LeGone | legone.name");
    }

    label c;
    button up, down;
    menu_bar mbar;
};

//  ----------------------------------------------------------------------------

int ts3plugin_offersConfigure()
{
	printf("PLUGIN: offersConfigure\n");

	return PLUGIN_OFFERS_CONFIGURE_NEW_THREAD;
}

void ts3plugin_configure(void* handle, void* qParentWidget)
{
    win my_window;

    my_window.wait_until_closed();
}

void ts3plugin_registerPluginID(const char* id)
{
	const size_t sz = strlen(id) + 1;
	pluginID = (char*)malloc(sz * sizeof(char));
	_strcpy(pluginID, sz, id);
	printf("PLUGIN: registerPluginID: %s\n", pluginID);
}

void ts3plugin_freeMemory(void* data)
{
	free(data);
}

int ts3plugin_onClientPokeEvent(::uint64 serverConnectionHandlerID, anyID fromClientID, const char* pokerName, const char* pokerUniqueIdentity, const char* message, int ffIgnored)
{
    anyID myID;

	if (ffIgnored) {
		return 1;
	}
	
    if (ts3Functions.getClientID(serverConnectionHandlerID, &myID) != ERROR_ok)
	{
        ts3Functions.logMessage("Error querying own client id", LogLevel_ERROR, "Plugin", serverConnectionHandlerID);
        return 1;
    }

    if (fromClientID != myID)
	{
		if (ts3Functions.requestSendPrivateTextMsg(serverConnectionHandlerID, "[COLOR=#ffcc22]Why do you poke me?! A bot?! I will tell [b]MASTER [u]LeGone[/u][/b] about this![/COLOR]", fromClientID, NULL) != ERROR_ok) {
            ts3Functions.logMessage("Error requesting send text message", LogLevel_ERROR, "Plugin", serverConnectionHandlerID);
        }
    }

    return 1;
}

unsigned char responseIndex;
std::string responses[10] = {
	"Hi, I am the SKYNET Global Defense Bot! Created by [b]Master LeGone[/b].",
	"Example Text 1",
	"Example Text 2",
	"Example Text 2",
	"Example Text 3",
	"Example Text 4",
	"Example Text 5",
	"Example Text 6",
	"Example Text 7",
	"Sample Text and close the window"
};
anyID lastSpamer;

int ts3plugin_onTextMessageEvent(::uint64 serverConnectionHandlerID, anyID targetMode, anyID toID, anyID fromID, const char* fromName, const char* fromUniqueIdentifier, const char* message, int ffIgnored)
{
	if (ffIgnored)
	{
		return 0;
	}

	anyID myID;
	if (ts3Functions.getClientID(serverConnectionHandlerID, &myID) != ERROR_ok)
	{
		ts3Functions.logMessage("Error querying own client id", LogLevel_ERROR, "Plugin", serverConnectionHandlerID);
		return 0;
	}

	if (fromID != myID)
	{
		if (lastSpamer == fromID)
		{
			if (responseIndex == 10)
			{
				ts3Functions.clientChatClosed(serverConnectionHandlerID, fromUniqueIdentifier, fromID, NULL);
				return (1);
			}
		}
		else
		{
			lastSpamer = fromID;
			responseIndex = 0;
		}

		std::string the_message = message;
		the_message = dlib::tolower(the_message);
		
		if (the_message == "on" || the_message == "enable")
		{
			bActive = true;
			
			if (ts3Functions.requestSendPrivateTextMsg(serverConnectionHandlerID, "Security [b]enabled[/b]", fromID, NULL) != ERROR_ok)
			{
				ts3Functions.logMessage("Error requesting send text message", LogLevel_ERROR, "Plugin", serverConnectionHandlerID);
			}
		}
		else if (the_message == "off" || the_message == "disable")
		{
			bActive = false;
			
			if (ts3Functions.requestSendPrivateTextMsg(serverConnectionHandlerID, "Security [b]disabled[/b]", fromID, NULL) != ERROR_ok)
			{
				ts3Functions.logMessage("Error requesting send text message", LogLevel_ERROR, "Plugin", serverConnectionHandlerID);
			}
		}
		else
		{
			if (ts3Functions.requestSendPrivateTextMsg(serverConnectionHandlerID, responses[responseIndex].c_str(), fromID, NULL) != ERROR_ok)
			{
				ts3Functions.logMessage("Error requesting send text message", LogLevel_ERROR, "Plugin", serverConnectionHandlerID);
			}

			++responseIndex;

			if (responseIndex == 10)
			{
				ts3Functions.clientChatClosed(serverConnectionHandlerID, fromUniqueIdentifier, fromID, NULL);
				return (1);
			}
		}

		return (0);
	}

    return (1);
}
