module gauntlet/api

go 1.22

require (
	gauntlet/broker v0.0.0
	gauntlet/control v0.0.0
	gauntlet/evidence v0.0.0
	gauntlet/governor v0.0.0
)

replace gauntlet/broker => ../broker

replace gauntlet/control => ../control-plane

replace gauntlet/evidence => ../evidence-plane

replace gauntlet/governor => ../governor
