import { useEffect, useMemo, useState } from "react";
import "./App.css";
import { E2EEHandler } from "./e2ee/e2ee";

function formDataToJson(formData: FormData): Record<string, unknown> {
  const obj: Record<string, unknown> = {};

  for (const [key, value] of formData.entries()) {
    obj[key] = value;
  }

  return obj;
}

function App() {
  const [publicKey, setPublicKey] = useState<CryptoKey>();
  const e2ee = useMemo(
    () => (publicKey ? new E2EEHandler(publicKey) : undefined),
    [publicKey],
  );
  const host = useMemo(() => import.meta.env.VITE_BACKEND_URL ?? "/api", []);

  useEffect(() => {
    // fetch server public key (response: { publicKey: "v1:<base64-of-PEM>" })
    fetch(`${host}/keys`)
      .then((r) => r.json())
      .then(async (data) => {
        const pkWithVersion: string = data.publicKey;
        const parts = pkWithVersion.split(":");
        if (parts.length < 2) return;
        const b64Pem = parts.slice(1).join(":");
        const pem = atob(b64Pem);
        // strip header/footer and newlines to get inner base64
        const pemHeader = "-----BEGIN PUBLIC KEY-----";
        const pemFooter = "-----END PUBLIC KEY-----";
        let inner = pem.replace(pemHeader, "").replace(pemFooter, "");
        inner = inner.replace(/\s+/g, "");
        const der = Uint8Array.from(atob(inner), (c) => c.charCodeAt(0));
        const key = await crypto.subtle.importKey(
          "spki",
          der.buffer,
          {
            name: "RSA-OAEP",
            hash: "SHA-256",
          },
          true,
          ["encrypt"],
        );
        setPublicKey(key);
      })
      .catch((err) => console.error("fetch public key failed", err));
  }, [host]);

  useEffect(() => {
    if (publicKey) {
      console.log("public key fetched");
    }
  }, [publicKey]);

  return (
    <>
      <h1>Onboarding</h1>

      <form
        onSubmit={async (e) => {
          e.preventDefault();
          const formData = formDataToJson(new FormData(e.currentTarget));
          // first step -- check duplication
          const { nationalId } = formData;
          try {
            const exists = await fetch(`${host}/profiles/existence`, {
              method: "POST",
              headers: {
                "Content-Type": "application/json",
              },
              body: JSON.stringify({ national_id: nationalId }),
            })
              .then((resp) => {
                if (!resp.ok) {
                  throw Error("server error");
                }
                return resp.json();
              })
              .then((result) => !!result.exists);
            if (exists) {
              alert("This National ID was already registered!");
              return;
            }
          } catch (err) {
            alert("server error when checking existence");
            console.error({ err });
            return;
          }
          await e2ee
            ?.encrypt(formData)
            .then((body) =>
              fetch(`${host}/profiles`, {
                method: "POST",
                headers: {
                  "Content-Type": "application/json",
                },
                body: JSON.stringify(body),
              }),
            )
            .then((resp) => {
              if (resp.ok) {
                alert("Successfully registered!");
              } else {
                alert("Failed to register");
              }
            });
        }}
      >
        <div>
          <label htmlFor="nationalId">National ID: </label>
          <input name="nationalId" type="text" placeholder="12 digits" />
        </div>
        {/* <div>
          <label htmlFor="firstName">First name: </label>
          <input name="firstName" type="text" placeholder="First Name" />
        </div>
        <div>
          <label htmlFor="lastName">Last name: </label>
          <input name="lastName" type="text" placeholder="Last Name" />
        </div> */}
        <br />
        <button type="submit">Submit</button>
      </form>
    </>
  );
}

export default App;
