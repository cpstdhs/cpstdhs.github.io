#!/bin/bash
#
cd /home/chatbot
exec 2>/dev/null
timeout 20 /home/chatbot/chatbot_server
