package decrypt

import (
	"strconv"
	"strings"
)

func debug(format string, a ...interface{}) (bool, error) {
	return false, nil
}

// validate checks that the vote is valid.
// TODO: Make sure this is in constant time.
func validate(poll PollMeta, vote voteValue) (bool, error) {
	if poll.MinAmount == 0 {
		poll.MinAmount = 1
	}

	if poll.MaxAmount == 0 {
		poll.MaxAmount = 1
	}

	options := strings.Split(poll.Options, ",")
	allowedOptions := make(map[int]bool, len(options))
	if poll.Options != "" {
		for _, o := range options {
			id, _ := strconv.Atoi(o)
			allowedOptions[id] = true
		}
	}

	allowedGlobal := map[string]bool{
		"Y": poll.GlobalYes,
		"N": poll.GlobalNo,
		"A": poll.GlobalAbstain,
	}

	switch poll.Method {
	case "Y", "N":
		switch vote.Type() {
		case ballotValueString:
			// The user answered with Y, N or A (or another invalid string).
			if !allowedGlobal[vote.str] {
				return debug("Global vote %s is not enabled", vote.str)
			}
			return true, nil

		case ballotValueOptionAmount:
			var sumAmount int
			for optionID, amount := range vote.optionAmount {
				if amount < 0 {
					return debug("Your vote for option %d has to be >= 0", optionID)
				}

				if !allowedOptions[optionID] {
					return debug("Option_id %d does not belong to the poll", optionID)
				}

				sumAmount += amount
			}

			if sumAmount < poll.MinAmount || sumAmount > poll.MaxAmount {
				return debug("The sum of your answers has to be between %d and %d", poll.MinAmount, poll.MaxAmount)
			}

			return true, nil

		default:
			return debug("Your vote has a wrong format")
		}

	case "YN", "YNA":
		switch vote.Type() {
		case ballotValueString:
			// The user answered with Y, N or A (or another invalid string).
			if !allowedGlobal[vote.str] {
				return debug("Global vote %s is not enabled", vote.str)
			}
			return true, nil

		case ballotValueOptionString:
			for optionID, yna := range vote.optionYNA {
				if !allowedOptions[optionID] {
					return debug("Option_id %d does not belong to the poll", optionID)
				}

				if yna != "Y" && yna != "N" && (yna != "A" || poll.Method != "YNA") {
					// Valid that given data matches poll method.
					return debug("Data for option %d does not fit the poll method.", optionID)
				}
			}
			return true, nil

		default:
			return debug("Your vote has a wrong format")
		}

	default:
		return debug("Your vote has a wrong format")
	}
}
