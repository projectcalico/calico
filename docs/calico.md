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
    <h3>Docker</h3>
    <a href="{{base}}/" class="button">Find out more</a>
  </div>
  <div class="col3rd">
    <h3>Kubernetes</h3>
    <a href="{{base}}/docs/getting-started/calico-integrations" class="button">Get Started</a>
  </div>
  <div class="col3rd">
    <h3>Mesos</h3>
    <a href="https://slack.projectcalico.org" class="button">Join our Slack</a>
  </div>
</div>
<div class="colContainer">
  <div class="col3rd">
  <h3>OpenStack</h3>
  <a href="{{base}}/community/contribute" class="button">Contribute to Calico</a>
  </div>
  <div class="col3rd">
  <h3>rkt</h3>
  <a href="{{base}}/docs/using-calico/troubleshooting/Troubleshooting" class="button">Troubleshooting</a>
  </div>
  <div class="col3rd">
  <h3>Host Protection</h3>
  <a href="{{base}}/docs/using-calico/troubleshooting/Troubleshooting" class="button">Troubleshooting</a>
  </div>
</div>
