import React, { useEffect, useMemo, useRef, useState } from "react";

const RECIPIENT_GROUPS = [
  { value: "public", label: "Public Users" },
  { value: "stakeholders", label: "Stakeholders & Partners" },
  { value: "regulators", label: "Regulators / Government" },
  { value: "internal", label: "Internal Response Team" },
];

const MESSAGE_TYPES = [
  { value: "incident_alert", label: "Incident Alert" },
  { value: "stakeholder_notice", label: "Stakeholder Notice" },
  { value: "status_update", label: "Status Update" },
  { value: "resolution", label: "Resolution" },
];
const MOCK_SEND_DELAY_MS = 900;

export default function UserCommunicationsInterface() {
  const [messageType, setMessageType] = useState("incident_alert");
  const [recipients, setRecipients] = useState(["public"]);
  const [referenceCode, setReferenceCode] = useState("INC-2026-001");
  const [subject, setSubject] = useState("");
  const [body, setBody] = useState("");
  const [sendStatus, setSendStatus] = useState("idle");
  const [statusText, setStatusText] = useState("No message sent yet.");
  const sendTimeoutRef = useRef(null);

  const trimmedSubject = subject.trim();
  const trimmedBody = body.trim();
  const canSend = trimmedSubject.length > 0 && trimmedBody.length > 0 && recipients.length > 0;

  const previewText = useMemo(() => {
    const recipientLabels = RECIPIENT_GROUPS.filter((group) => recipients.includes(group.value)).map((group) => group.label);

    return [
      `Type: ${messageType}`,
      `Reference: ${referenceCode || "N/A"}`,
      `Recipients: ${recipientLabels.join(", ") || "None selected"}`,
      "",
      `Subject: ${subject || "(add a subject)"}`,
      "",
      body || "(compose your message body)",
    ].join("\n");
  }, [body, messageType, recipients, referenceCode, subject]);

  const handleRecipientToggle = (value) => {
    setRecipients((current) => {
      if (current.includes(value)) {
        return current.filter((recipient) => recipient !== value);
      }
      return [...current, value];
    });
  };

  const handleSend = () => {
    if (!canSend || sendStatus === "sending") {
      return;
    }

    setSendStatus("sending");
    setStatusText("Sending message...");

    if (sendTimeoutRef.current) {
      window.clearTimeout(sendTimeoutRef.current);
    }

    sendTimeoutRef.current = window.setTimeout(() => {
      setSendStatus("sent");
      setStatusText(`Message sent to ${recipients.length} recipient group(s).`);
      sendTimeoutRef.current = null;
    }, MOCK_SEND_DELAY_MS);
  };

  const handleReset = () => {
    if (sendTimeoutRef.current) {
      window.clearTimeout(sendTimeoutRef.current);
      sendTimeoutRef.current = null;
    }
    setSubject("");
    setBody("");
    setSendStatus("idle");
    setStatusText("Composer reset. Ready for next communication.");
  };

  useEffect(
    () => () => {
      if (sendTimeoutRef.current) {
        window.clearTimeout(sendTimeoutRef.current);
      }
    },
    []
  );

  return (
    <section style={{ border: "1px solid #d0d7de", borderRadius: "8px", padding: "16px", maxWidth: "960px" }}>
      <h2 style={{ marginTop: 0 }}>User Communications Interface</h2>
      <p style={{ marginTop: "0.25rem", color: "#57606a" }}>
        Compose, preview, and send mock public or stakeholder alerts for crisis communication workflows.
      </p>

      <div style={{ display: "grid", gap: "12px", gridTemplateColumns: "repeat(auto-fit, minmax(280px, 1fr))" }}>
        <label>
          Message Type
          <select value={messageType} onChange={(event) => setMessageType(event.target.value)} style={{ display: "block", width: "100%", marginTop: "6px" }}>
            {MESSAGE_TYPES.map((type) => (
              <option key={type.value} value={type.value}>
                {type.label}
              </option>
            ))}
          </select>
        </label>

        <label>
          Reference Code
          <input
            type="text"
            value={referenceCode}
            onChange={(event) => setReferenceCode(event.target.value)}
            style={{ display: "block", width: "100%", marginTop: "6px" }}
          />
        </label>
      </div>

      <fieldset style={{ marginTop: "12px", border: "1px solid #d0d7de", borderRadius: "6px", padding: "10px" }}>
        <legend>Recipients</legend>
        {RECIPIENT_GROUPS.map((group) => (
          <label key={group.value} style={{ display: "block", marginBottom: "4px" }}>
            <input type="checkbox" checked={recipients.includes(group.value)} onChange={() => handleRecipientToggle(group.value)} /> {group.label}
          </label>
        ))}
      </fieldset>

      <label style={{ display: "block", marginTop: "12px" }}>
        Subject
        <input type="text" value={subject} onChange={(event) => setSubject(event.target.value)} style={{ display: "block", width: "100%", marginTop: "6px" }} />
      </label>

      <label style={{ display: "block", marginTop: "12px" }}>
        Message Body
        <textarea
          value={body}
          onChange={(event) => setBody(event.target.value)}
          rows={8}
          style={{ display: "block", width: "100%", marginTop: "6px", resize: "vertical" }}
        />
      </label>

      <div style={{ marginTop: "12px", display: "flex", gap: "8px", flexWrap: "wrap" }}>
        <button type="button" onClick={handleSend} disabled={!canSend || sendStatus === "sending"}>
          {sendStatus === "sending" ? "Sending..." : "Send Alert"}
        </button>
        <button type="button" onClick={handleReset}>
          Reset
        </button>
      </div>

      <p style={{ marginTop: "10px" }}>
        <strong>Send Status:</strong> {statusText}
      </p>

      <h3>Preview</h3>
      <pre
        style={{
          background: "#f6f8fa",
          border: "1px solid #d0d7de",
          borderRadius: "6px",
          padding: "12px",
          overflowX: "auto",
          whiteSpace: "pre-wrap",
        }}
      >
        {previewText}
      </pre>
    </section>
  );
}
