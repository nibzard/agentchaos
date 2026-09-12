module gauntlet/supervisor

go 1.22

require (
	gauntlet/broker v0.0.0
	gauntlet/evidence v0.0.0
)

replace gauntlet/broker => ../broker

replace gauntlet/evidence => ../evidence-plane
