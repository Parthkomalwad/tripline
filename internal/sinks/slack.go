package sinks

// Slack incoming webhook payload, from the official docs
// (https://docs.slack.dev/messaging/sending-messages-using-incoming-webhooks,
// formerly https://api.slack.com/messaging/webhooks):
//
//	POST <webhook URL>
//	Content-type: application/json
//	{ "text": "Hello, world." }
//
// Success is HTTP 200 with the plain text body "ok". Other fields such as
// "blocks" may be added. Section block, from
// https://docs.slack.dev/reference/block-kit/blocks/section-block:
//
//	{ "type": "section", "text": { "type": "mrkdwn", "text": "..." } }
//
// The section text is 1 to 3000 characters. "text" stays as the fallback
// for notifications.

const slackMax = 3000

type slackText struct {
	Type string `json:"type"`
	Text string `json:"text"`
}

type slackBlock struct {
	Type string    `json:"type"`
	Text slackText `json:"text"`
}

type slackMsg struct {
	Text   string       `json:"text"`
	Blocks []slackBlock `json:"blocks"`
}

func slackPayload(a Alert) any {
	t := a.Text()
	if len(t) > slackMax {
		t = t[:slackMax-3] + "..."
	}
	return slackMsg{Text: t, Blocks: []slackBlock{{"section", slackText{"mrkdwn", t}}}}
}
