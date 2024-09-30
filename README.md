# 𝐎𝐬𝐢𝐧𝐭 𝐒𝐜𝐫𝐢𝐩𝐭 | 𝐆𝐚𝐭𝐡𝐞𝐫 𝐀𝐥𝐥 𝐢𝐧𝐬𝐭𝐚 𝐀𝐜𝐜𝐨𝐮𝐧𝐭 ♥️
import os
import requests
from uuid import uuid4 as uid
from secrets import token_hex
import instaloader
from colored import fg, attr
import time

# ASCII Banner
def print_banner():
    banner = """

__   __ _    ____    _    ____  
\ \ / // \  / ___|  / \  |  _ \ 
 \ V // _ \ \___ \ / _ \ | |_) |
  | |/ ___ \ ___) / ___ \|  _ < 
  |_/_/   \_\____/_/   \_\_| \_\.... Hacking its my property🚀👩‍💻                    
    """
    print(fg('cyan') + banner + attr('reset'))

# Animation for gathering info
def animate_message(message):
    for c in message:
        print(fg('green') + c + attr('reset'), end='', flush=True)
        time.sleep(0.1)
    print()

def main():
    os.system('clear')
    print_banner()

    user = input(fg('yellow') + "Please enter your Instagram username: " + attr('reset'))
    animate_message("Gathering information, please wait...")
    
    csr = token_hex(8) * 2
    headers = {
        "Content-Type": "application/x-www-form-urlencoded; charset=UTF-8",
        "Host": "i.instagram.com",
        "Connection": "Keep-Alive",
        "User-Agent": "Instagram 10.26.0 Android",
        "Cookie": "mid=YwvCRAABAAEsZcmT0OGJdPu3iLUs; csrftoken=" + csr,
        "Cookie2": "$Version=1",
        "Accept-Language": "en-US",
        "X-IG-Capabilities": "AQ==",
        "Accept-Encoding": "gzip",
    }
    data = {
        "q": user,
        "device_id": f"android{uid()}",
        "guid": str(uid()),
        "_csrftoken": csr
    }
    response = requests.post('https://i.instagram.com/api/v1/users/lookup/', headers=headers, data=data).json()
    email = response.get('obfuscated_email', 'N/A')
    user_id = response.get('user', {}).get('pk', 'N/A')
    is_private = response.get('user', {}).get('is_private', 'N/A')
    has_phone = response.get('has_valid_phone', 'N/A')
    can_email_reset = response.get('can_email_reset', 'N/A')
    can_sms_reset = response.get('can_sms_reset', 'N/A')
    can_wa_reset = response.get('can_wa_reset', 'N/A')
    fb_login_option = response.get('fb_login_option', 'N/A')
    phone_number = response.get('phone_number', 'N/A')

    profile_info = ""
    try:
        L = instaloader.Instaloader()
        profile = instaloader.Profile.from_username(L.context, user)
        profile_info = (
            f"{fg('cyan')}[+] Username: {profile.username}{attr('reset')}\n" +
            f"{fg('cyan')}[+] ID: {profile.userid}{attr('reset')}\n" +
            f"{fg('cyan')}[+] Full Name: {profile.full_name}{attr('reset')}\n" +
            f"{fg('cyan')}[+] Biography: {profile.biography}{attr('reset')}\n" +
            f"{fg('cyan')}[+] Business Category Name: {profile.business_category_name}{attr('reset')}\n" +
            f"{fg('cyan')}[+] External URL: {profile.external_url}{attr('reset')}\n" +
            f"{fg('cyan')}[+] Followed by Viewer: {profile.followed_by_viewer}{attr('reset')}\n" +
            f"{fg('cyan')}[+] Followees: {profile.followees}{attr('reset')}\n" +
            f"{fg('cyan')}[+] Followers: {profile.followers}{attr('reset')}\n" +
            f"{fg('cyan')}[+] Follows Viewer: {profile.follows_viewer}{attr('reset')}\n" +
            f"{fg('cyan')}[+] Blocked by Viewer: {profile.blocked_by_viewer}{attr('reset')}\n" +
            f"{fg('cyan')}[+] Has Blocked Viewer: {profile.has_blocked_viewer}{attr('reset')}\n" +
            f"{fg('cyan')}[+] Has Highlight Reels: {profile.has_highlight_reels}{attr('reset')}\n" +
            f"{fg('cyan')}[+] Has Public Story: {profile.has_public_story}{attr('reset')}\n" +
            f"{fg('cyan')}[+] Has Requested Viewer: {profile.has_requested_viewer}{attr('reset')}\n" +
            f"{fg('cyan')}[+] Requested by Viewer: {profile.requested_by_viewer}{attr('reset')}\n" +
            f"{fg('cyan')}[+] Has Viewable Story: {profile.has_viewable_story}{attr('reset')}\n" +
            f"{fg('cyan')}[+] IGTV Count: {profile.igtvcount}{attr('reset')}\n" +
            f"{fg('cyan')}[+] Is Business Account: {profile.is_business_account}{attr('reset')}\n" +
            f"{fg('cyan')}[+] Is Private: {profile.is_private}{attr('reset')}\n" +
            f"{fg('cyan')}[+] Is Verified: {profile.is_verified}{attr('reset')}\n" +
            f"{fg('cyan')}[+] Media Count: {profile.mediacount}{attr('reset')}\n" +
            f"{fg('cyan')}[+] Profile Picture URL: {profile.profile_pic_url}{attr('reset')}\n"
        )
    except Exception as e:
        profile_info = "Could not retrieve additional profile information."

    lookup_result = (
        f"{fg('yellow')}[+] Username :{user}{attr('reset')}\n" +
        f"{fg('yellow')}[+] User ID : {user_id}{attr('reset')}\n" +
        f"{fg('yellow')}[+] Is Private : {is_private}{attr('reset')}\n" +
        f"{fg('yellow')}[+] Email : {email}{attr('reset')}\n" +
        f"{fg('yellow')}[+] Has Phone Number : {has_phone}{attr('reset')}\n" +
        f"{fg('yellow')}[+] Email Reset : {can_email_reset}{attr('reset')}\n" +
        f"{fg('yellow')}[+] SMS Reset : {can_sms_reset}{attr('reset')}\n" +
        f"{fg('yellow')}[+] WhatsApp Reset : {can_wa_reset}{attr('reset')}\n" +
        f"{fg('yellow')}[+] Facebook Login : {fb_login_option}{attr('reset')}\n" +
        f"{fg('yellow')}[+] Phone Number : {phone_number}{attr('reset')}\n\n" +
        profile_info
    )

    print(lookup_result)

    reset_option = input(fg('yellow') + "Do you want to send a reset email? Type Y for Yes or N for No: " + attr('reset')).lower()
    if reset_option == 'y':
        animate_message("Sending reset email, please wait...")
        csr = token_hex(8) * 2
        headers = {
            "Content-Type": "application/x-www-form-urlencoded; charset=UTF-8",
            "Host": "i.instagram.com",
            "Connection": "Keep-Alive",
            "User-Agent": "Instagram 10.26.0 Android",
            "Cookie": "mid=YwvCRAABAAEsZcmT0OGJdPu3iLUs; csrftoken=" + csr,
            "Cookie2": "$Version=1",
            "Accept-Language": "en-US",
            "X-IG-Capabilities": "AQ==",
            "Accept-Encoding": "gzip",
        }
        data = {
            "user_email": user,
            "device_id": f"android{uid()}",
            "guid": str(uid()),
            "_csrftoken": csr
        }
        reset_response = requests.post('https://i.instagram.com/api/v1/accounts/send_password_reset/', data=data, headers=headers)
        reset_result = reset_response.json()
        if 'obfuscated_email' in reset_result:
            email = reset_result['obfuscated_email']
            print(fg('green') + '[√] Done Send Reset: ' + email + attr('reset'))
        else:
            print(fg('red') + '[×] Error Sending Reset' + attr('reset'))
    else:
        print(fg('red') + 'Operation canceled.' + attr('reset'))

if __name__ == '__main__':
    main()

    𝐅𝐮𝐥𝐥 𝐬𝐭𝐞𝐩 𝐌𝐬𝐠 𝐅𝐨𝐫 𝐌𝐲 𝐏𝐚𝐠𝐞♥️
