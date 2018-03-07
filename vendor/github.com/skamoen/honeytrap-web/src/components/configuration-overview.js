import React, { Component } from 'react';
import { connect } from 'react-redux';
import { bindActionCreators } from 'redux';
import { addSession, fetchSessions } from '../actions/index';
import { Link } from 'react-router';
import View from './view';

class ConfigurationOverview extends Component {
  constructor(props) {
    super(props);
  }

  componentWillMount() {
    const { dispatch } = this.props;
  }

  renderTable() {}

  render() {
    return ( 
	<View title = "Setup" subtitle = "Instructions" >
		<h2>Honeytrack</h2>
		<p>
			The Honeytrack project is a thesis project, researching attacks on Internet of Things devices using Telnet. 
			You can participate in this project, and monitor attacks on your own IP address!
			For this, we use the honey<b>trap</b> agent, from the project Honeytrack is based on.
			The Honeytrap agent is a small lightweight honeypot listener that forwards traffic to our central Honeytrack server.
			All traffic is fowarded to the central server, so you're not actually running a telnet server on your device.
		</p>
		<h2>Installation</h2>
		<p>
			The Honeytrack agent comes as a preconfigured .deb package for the ARM architecture. 
			This package is suitable for all ARM based devices such as the Raspberry Pi, running a Debian-based distribution like Armbian, Raspbian, or Ubuntu Core.
			If you would like to participate but don't have a device with the above requirements, instructions for installation from source are below.
		</p>
		<p>
			The package can be downloaded from <a href="https://www.networksecuritycourse.nl/honeytrap-agent-arm.deb">here</a>, 
			or with <code>wget https://www.networksecuritycourse.nl/honeytrap-agent-arm.deb</code>
			After you downloaded the package, install it with <code>sudo dpkg -i honeytrack-agent-arm.deb</code>.
			This installs the application and configuration suitable for participation in the experiment.
			You can start the Honeytrack Agent with <code>sudo service honeytrap-agent start</code>.
			The agent will now start in the background and retrieve its configuration from our server.
			In the current configuration, the Agent is instructed to listen on port 23, the default port for the Telnet protocol.
		</p>
		<p>
			For this to work, it is expected that traffic on port 23 is forwarded to your device.
			This has to be configured in your router, often under "Port Forwarding", "NAT", or "Firewall". 
			Please check <a href="https://portforward.com/router.htm">this website</a> if you need help.
		</p>
		<p>
			To summarize:<br /><br />
			<code>wget https://www.networksecuritycourse.nl/honeytrap-agent-arm.deb</code><br />
			<code>sudo dpkg -i honeytrack-agent-arm.deb</code><br />
			<code>sudo service honeytrap-agent start</code><br />
		</p>
		<h2>Installation from source</h2>
		<p>
			Alternatively, you can build the agent from source. For this, you need Go(lang) installed, at least version 1.8.
			Once Go is installed, get the package with <code>go get github.com/honeytrap/honeytrap-agent</code>, <code>cd $GOPATH/src/github.com/honeytrap/honeytrap-agent</code>
			finally build with <code>go build -o bin/honeytrap-agent</code>. Create a configuration file called <code>config.toml</code>, with the following content:
		</p>

		<code>server="honeytrack.cyber-threat-intelligence.com:12000"</code><br />
		<code>remote-key="a842e2a34911b311e40892da583185fb3ba0748f1931bfcc53f6e5e16898ff06"</code><br />

		<p>
			You can then run the agent with <code>sudo ./honeytrap-agent -f config.toml</code>. Note that the agent runs in the foreground.
			You need to run it in a <code>screen</code> session or use something like <code>nohup</code> to run it in the background
		</p> 
		<h2>Honeytrack Usage</h2>
		<p>
			By going to this website, you can track events happening on your device.
			On the Dashboard, you can see two columns.
			The Last Attack columns displays attacks on the IP address you're visiting the website from.
			If you want to see attacks on your agent, visit the website from the same place as your device!
			The second column Origin shows the Honeytrack Agent totals per country, so all participants are combined.

			On the Events page you can find some more details on the attacks.
		</p>
	</View>
    );
  }
}

function mapStateToProps(state) {
  return {};
}

export default connect(mapStateToProps)(ConfigurationOverview);