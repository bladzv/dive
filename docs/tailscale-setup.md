# Tailscale — Remote Access

Tailscale lets you access the dashboard from anywhere — your phone, a coffee shop, a different country — without exposing anything to the open internet. It creates an encrypted private network between your devices using a technology called WireGuard.

**Time:** approximately 10 minutes.

← [Raspberry Pi Setup](raspberry-pi-setup.md) | Back to [Setup Guide](../SETUP.md)

---

## How It Works

Without Tailscale, the dashboard is only reachable when your device is on the same Wi-Fi as the Pi.

With Tailscale, every device you add gets a permanent private IP address in the `100.x.x.x` range. These addresses only work between devices in your Tailscale network — no one else can reach them. The connection is end-to-end encrypted with WireGuard, so even though traffic travels over the internet, it is private and secure.

**Tailscale is free** for personal use (up to 100 devices).

---

## Step 1 — Create a Tailscale Account

Go to **tailscale.com** on your Mac and sign up for a free account. You can sign in with Google, GitHub, or Microsoft — no separate password is needed.

---

## Step 2 — Install Tailscale on Your Mac

1. Go to **tailscale.com/download** and download the Mac app
2. Open the downloaded file and follow the installation steps
3. Once installed, a Tailscale icon appears in your Mac's menu bar (top-right area of the screen)
4. Click the icon → **Log in** → sign in with the same account you just created

After signing in, clicking the menu bar icon shows your Mac's Tailscale IP address (starts with `100.`). That is your Mac's private address on the Tailscale network.

---

## Step 3 — Install Tailscale on the Raspberry Pi

Connect to your Pi via SSH, then run the official install script:

```bash
$ curl -fsSL https://tailscale.com/install.sh | sh
```
- `curl` — downloads a file from the internet.
- `-fsSL` — a combination of flags: `-f` exits cleanly on errors, `-s` hides the progress bar, `-S` still shows error messages if something goes wrong, `-L` follows URL redirects.
- `https://tailscale.com/install.sh` — the official Tailscale install script directly from their website.
- `| sh` — sends the downloaded script directly to the shell to run it immediately. This is Tailscale's officially documented installation method.

> **Security note:** this runs a script downloaded from the internet directly in your shell. This is Tailscale's officially documented method and the script is served over HTTPS. If you prefer to inspect the script before running it, download it first (`curl -fsSL https://tailscale.com/install.sh -o install-tailscale.sh`), review it, then run `sh install-tailscale.sh`.

---

## Step 4 — Connect the Pi to Your Tailscale Network

```bash
$ sudo tailscale up
```
- `tailscale up` — starts Tailscale and initiates the process of connecting this device to your network.
- `sudo` — required because Tailscale needs administrator access to create a network interface on the Pi.

The command will print a URL in the terminal:
```
To authenticate, visit:
https://login.tailscale.com/a/xxxxxxxxxxxxxxxx
```

Open that URL in a browser on your Mac and sign in with your Tailscale account. Once you authenticate, the terminal on the Pi will show that it's connected, and you'll see the Pi appear in your Tailscale device list at **login.tailscale.com/admin/machines**.

Get the Pi's Tailscale IP address:
```bash
$ tailscale ip -4
```
- `-4` — shows only the IPv4 address (the `100.x.x.x` one, not the longer IPv6 address).

You'll see something like `100.101.102.103`. Write this down — you can use it to reach the dashboard from anywhere.

---

## Step 5 — Update the Firewall

The firewall rule you added in the Pi setup only allows your home network. You need one more rule to allow connections coming through Tailscale.

```bash
$ sudo ufw allow in on tailscale0 to any port 8000
```
- `allow in on tailscale0` — allows incoming connections that arrive through the `tailscale0` interface. This is the virtual network interface Tailscale creates on your Pi. Only traffic from your authenticated Tailscale devices comes through this interface — so this rule is precisely scoped.
- `to any port 8000` — specifically for the dashboard port.

Apply the change:
```bash
$ sudo ufw reload
```
- `reload` — re-reads and applies all firewall rules without disrupting any existing connections.

Confirm the new rule is in the list:
```bash
$ sudo ufw status
```
You should see a new entry for port `8000` on `tailscale0`.

---

## Step 6 — Enable Tailscale to Start on Boot

```bash
$ sudo systemctl enable tailscaled
```
- `systemctl enable` — marks a service to start automatically every time the Pi boots.
- `tailscaled` — the name of Tailscale's background service (the `d` at the end stands for "daemon", which is the Linux term for a background service).

Without this step, Tailscale would need to be manually started after every Pi reboot.

---

## Step 7 — Access the Dashboard Remotely

You can now reach the dashboard from any device connected to your Tailscale network, regardless of where you are.

**Option A — By Tailscale IP:**
```
http://100.101.102.103:8000
```
Replace `100.101.102.103` with your Pi's actual Tailscale IP from Step 4.

**Option B — By hostname (MagicDNS):**
```
http://raspberrypi:8000
```
Tailscale's MagicDNS feature automatically gives each device a hostname you can use instead of the IP. The hostname is just the device's name — no `.local` suffix. MagicDNS is enabled by default on new Tailscale accounts. You can check or enable it at **login.tailscale.com/admin/dns**.

> **Note:** both devices need Tailscale active and connected for remote access to work. On your Mac, the menu bar icon should show a green dot. On the Pi, you can verify with `tailscale status`. If either is disconnected, use the local IP (`http://192.168.x.x:8000`) when on the same home network.

---

## Step 8 — Optional: Add Other Devices

You can access the dashboard from your phone, tablet, or any other device by installing Tailscale on it and signing in with the same account.

- **iPhone / iPad** — search "Tailscale" in the **App Store**
- **Android** — search "Tailscale" in the **Play Store**
- **Windows** — download from **tailscale.com/download**

After signing in on any device, the dashboard URL (`http://raspberrypi:8000` or `http://100.x.x.x:8000`) works from that device anywhere with an internet connection.

---

## Troubleshooting

**Dashboard not loading remotely:**
1. Check that Tailscale is active on both devices: on your Mac, look for the green icon in the menu bar; on the Pi, run `tailscale status`
2. Confirm the firewall rule was added: run `sudo ufw status` on the Pi and check for `8000` on `tailscale0`
3. Try the Tailscale IP directly instead of the hostname — if the IP works but the hostname doesn't, MagicDNS may need to be enabled at `login.tailscale.com/admin/dns`

**Pi disappeared from Tailscale device list:**
```bash
$ sudo tailscale up
```
This re-authenticates the Pi. You may need to visit the auth URL again.

**Re-checking the Pi's Tailscale IP:**
```bash
$ tailscale ip -4
```
