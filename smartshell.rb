
require "smartcard"
require "hexy"

require 'tlv'
require 'tlv/parser/dictionaries/dictionaries'

require './crypto.rb'

PSE = "1PAY.SYS.DDF01"
VSDC= "\xa0\x00\x00\x00\x03\x10\x10"
DICT = TLV::DICTIONARIES["EMV"]
PIN = "\x24\x12\x34\xff\xff\xff\xff\xff"

AMOUNT1="\x00\x00\x00\x00\x01\x00"
AMOUNT2="\x00\x00\x00\x00\x00\x00"
TERM_COUNTRY="\x08\x26"
TVR="\x00\x00\x00\x00\x00"
TX_CURR=TERM_COUNTRY
TX_DATE="\x10\x10\x10"
TX_TYPE="\x00"
RND="\x12\x34\x56\x78"
CDOL1 = AMOUNT1+AMOUNT2+TERM_COUNTRY+TVR+TX_CURR+TX_DATE+TX_TYPE+RND
CDOL2 = "\x00\x00"+CDOL1

def hexy str
  puts Hexy.dump str
end

def tlv str
  puts TLV.parse(str, DICT)
end

def readers
  @ctx  ||= Smartcard::PCSC::Context.new
  @readers ||= @ctx.readers
  @readers
end

def card reader=readers[0]
  @ctx  ||= Smartcard::PCSC::Context.new
  @card ||= Smartcard::PCSC::Card.new(@ctx, reader)
  @card
end

def show_card card=card()
  info = card.info
  puts "Reader  : #{info[:readers][0]}"
  puts "Protocol: #{info[:protocol]}"
  puts "ATR     : \n  #{Hexy.dump(info[:atr])}"
end

def print_apdu cla, ins, p1, p2, le=0, data=nil
  l = 0
  if data != nil
    l = data.length
  else
    l = le
  end
  puts "|CLA|INS|P1|P2|Lx|"
  puts ("| %02x| %02x|%02x|%02x|%02x|" % [cla, ins, p1, p2, l])

  if data 
    hexy(data)
  end
end

def send_apdu cla, ins, p1, p2, le=0, data=nil, card=card()
  @sent_data = ""
  @sent_data << cla
  @sent_data << ins
  @sent_data << p1
  @sent_data << p2
  if data == nil
    @sent_data << le
  else
    @sent_data << data.length
    @sent_data << data
  end
  
  print_apdu cla, ins, p1, p2, le, data
  @rresponse = card.transmit(@sent_data)
  hexy(@rresponse)
  if @rresponse[0] == 0x61
    @rresponse = get_response @rresponse[1], card
  end
  @response = @rresponse[0, @rresponse.length-2]
  @sw12     = @rresponse[-2,2]
  @rresponse
end

def get_response le, card=card()
  puts "GET RESPONSE"
  send_apdu 0x00, 0xc0, 0x00, 0x00, le, nil, card
end

def read_record sfi, rec, card=card()
  puts "READ RECORD (sfi=#{sfi} rec=#{rec})"
  resp = send_apdu 0x00, 0xB2, rec, ((sfi << 3) | 0x04), 00, nil, card
  if resp[0] == 0x6c
    send_apdu 0x00, 0xB2, rec, ((sfi << 3) | 0x04), resp[1], nil, card
  end
end

def get_po card=card()
  puts "GET PROCESSING OPTIONS"
  send_apdu 0x80, 0xa8, 0x00, 0x00, 0x00, "\x83\x00"
  @aip = @response[2,2]
  @afl = @response[4,@response.length]
  @rresponse
end

def read_records afl=@afl
  num = afl.length / 4
  0.upto(num-1) { |i|
    sfi  = afl[i * 4] >> 3
    from = afl[(i*4)+1]
    to   = afl[(i*4)+2]
    from.upto(to) {|rec|
      read_record(sfi, rec)
      # save all the stuff ...
      tlv = TLV._parse(@response).first
      @card_data ||= []
      tlv.children.each {|child|
        @card_data.push(child)
      }
    }
  }
end

ATC="\x9f\x36"
LAST_ONLINE_ATC="\x9f\x13"
PIN_TRY_CTR="\x9f\x17"
LOG_FMT="\x9f\x4f"

def get_data tag
  resp = send_apdu 0x80, 0xca, tag[0], tag[1], 0x00
  if resp[0] == 0x6c
    send_apdu 0x80, 0xca, tag[0], tag[1], resp[1]
  end
end

def first_gen_ac
  puts "First Generate Application Cryptogram"
  send_apdu 0x80, 0xae, 0x40, 0x00, 0x00, CDOL1
end

def second_gen_ac
  puts "Second Generate Application Cryptogram"
  send_apdu 0x80, 0xae, 0x40, 0x00, 0x00, CDOL2
end

def verify pin
  send_apdu 0x00, 0x20, 0x00, 0x80, 0x00, pin
end

def dump_card_data
  "\n"+TLV._dump(@card_data, DICT)
end

def select aid, card=card()
  puts "SELECT"
  send_apdu 0x00, 0xa4, 0x04, 0x00, 00, aid, card
end



def quit
  @card.disconect
  exit
end
