module agentchaos/api

go 1.22

require (
	agentchaos/broker v0.0.0
	agentchaos/control v0.0.0
	agentchaos/evidence v0.0.0
	agentchaos/governor v0.0.0
)

replace agentchaos/broker => ../broker

replace agentchaos/control => ../control-plane

replace agentchaos/evidence => ../evidence-plane

replace agentchaos/governor => ../governor
