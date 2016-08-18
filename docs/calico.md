---
title: Project Calico
---
<style>
h2, h3, h4 {
  border-bottom: 0px !important;
}
.colContainer {
  padding-top:2px;
  padding-left: 2px;
  overflow: auto;
}
#samples a {
  color: #000;
}
.col3rd {
  display: block;
  width: 250px;
  float: left;
  margin-right: 30px;
  margin-bottom: 30px;
  overflow: hidden;
}
.col3rd h3, .col2nd h3 {
  margin-bottom: 0px !important;
}
.col3rd .button, .col2nd .button {
  margin-top: 20px;
  border-radius: 2px;
}
.col3rd p, .col2nd p {
  margin-left: 2px;
}
.col2nd {
  display: block;
  width: 400px;
  float: left;
  margin-right: 30px;
  margin-bottom: 30px;
  overflow: hidden;
}
.shadowbox {
  display: inline;
  float: left;
  text-transform: none;
  font-weight: bold;
  text-align: center;
  text-overflow: ellipsis;
  white-space: nowrap;
  overflow: hidden;
  line-height: 24px;
  position: relative;
  display: block;
  cursor: pointer;
  box-shadow: 0 2px 2px rgba(0,0,0,.24),0 0 2px rgba(0,0,0,.12);
  border-radius: 10px;
  background: #fff;
  transition: all .3s;
  padding: 16px;
  margin: 0 16px 16px 0;
  text-decoration: none;
  letter-spacing: .01em;
}
.shadowbox img {
    min-width: 150px;
    max-width: 150px;
    max-height: 50px;
}
</style>

This documentation is for Calico version {{ page.version }} - for earlier versions, see [here]({{base}}/docs/version).

Calico version {{ page.version }} supports integrations with Kubernetes, Docker, Mesos (including DC/OS) and OpenStack.  See [here]({{base}}/docs/reference/supported-platforms) for information on the versions supported by this release.
<p></p>
<div class="colContainer">
  <div class="col3rd">
    <h3>What is Calico?</h3>
    <p>Calico is an open source solution for networking and securing cloud-native applications running in containers, virtual machines or even bare-metal workloads.  Calico is built from the ground up with the pillars of simplicity, security and scalability. Calico is based on the same scalable IP networking principles as the internet and can be deployed without encapsulation or overlats to provide high performance at massive scales.</p>
    <a href="{{base}}/docs/what-is-calico/what-is-calico" class="button">Find out more</a>
  </div>
  <div class="col3rd">
    <h3>Installation guides</h3>
    <p>Calico is integrated with various environments include Kubernetes, Mesos, Docker and OpenStack.  These guides will help you get started in each of these environments.</p>
    <a href="{{base}}/docs/getting-started/calico-integrations" class="button">Get Started</a>
  </div>
  <div class="col3rd">
    <h3>Join our Slack community</h3>
    <p>Calico has a enthusiastic user community on Slack, which is the best place to ask for help, get in touch with the team or simply chat about Calico.</p>
    <a href="https://slack.projectcalico.org" class="button">Join our Slack</a>
  </div>
</div>

Use the links above and to the left to navigate around the Calico Docs.
<p>
</p>

<div class="colContainer">
  <div class="col2nd">
  <h3>Contribute to Calico</h3>
  <p>Calico is an open source project, and we're always happy to take contributions (both to the code and to these docs).  Look at our contribution guidelines to see how you can help shape the project.</p>
  <a href="{{base}}/community/contribute" class="button">Contribute to Calico</a>
  </div>
  <div class="col2nd">
  <h3>Need Help?</h3>
  <p>Try consulting our <a href="{{base}}/docs/using-calico/troubleshooting/Troubleshooting">troubleshooting guides</a> or join our community of users and contributors in <a href="https://slack.projectcalico.org>">our Slack community</a>.</p>
  <a href="{{base}}/docs/using-calico/troubleshooting/Troubleshooting" class="button">Troubleshooting</a>
  </div>
</div>