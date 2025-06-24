-- local starttime = os.epoch("local")
-- tokenizer
if not CPULib then
	include("wire/cpulib.lua")
end

if not tinyToken then
	AddCSLuaFile("wire/client/tinyToken.lua")
	include("wire/client/tinyToken.lua")
end

local fuzz,unfuzz = tinyToken.fuzz,tinyToken.unfuzz

local smatch = string.match

local TOKEN_PATTERNS = {
	REGISTER = {
		"EAX",
		"EBX",
		"ECX",
		"EDX",
		"ESI",
		"EDI",
		"EBP",
		"ESP",
	},
	SEGMENT = {
		"CS",
		"DS",
		"SS",
		"ES",
		"FS",
		"GS",
		"LS",
		"KS",
	},
	COMMENT = {
		"//.*"
	},
	MULTI_COMMENT_START = {
		"/%*"
	},
	MULTI_COMMENT_END = {
		"%*/"
	},
	OPAREN = {"%("},
	CPAREN = {"%)"},
	OSQUARE = {"%["},
	CSQUARE = {"%]"},
	COMMA = {"%,"},
	PERIOD = {"%."},
	INSTRUCTION = {}, -- fill from inst set
	INST_0 = {}, -- zero arg instructions
	STRING = {
		"\"[^\n%\"]*\"",
		"'[^\n%\']*'"
	},
	LITERAL = {"$'[^']?[^']?[^']?[^']?'"},
	NUMBER = {
		"0[xX]%x+", -- hexadecimal
		"%d+%.?%d*e[+-]?%d*", -- scientific
		"%d+%.?%d*", -- decimal
		-- "0[bB][01]+" -- binary (maybe one day)
	},
	OP_ASSIGN = {
		"%="
	},
	OP_EQ = {
		"%=%="
	},
	OP_NEQ = {
		"%!%="
	},
	OP_GT = {
		"%>"
	},
	OP_GTE = {
		"%>%="
	},
	OP_LT = {
		"%<"
	},
	OP_LTE = {
		"%<%="
	},
	OP_LAND = {
		"&&"
	},
	OP_LOR = {
		"%|%|"
	},
	OP_BAND = {
		"%&"
	},
	OP_BOR = {
		"%|"
	},
	OP_BXOR = {
		"%^"
	},
	OP_PLUS = {
		"%+"
	},
	OP_MINUS = {
		"%-"
	},
	OP_MULT = {
		"%*"
	},
	OP_DIV = {
		"%/"
	},
	OP_MOD = {
		"%%"
	},
	ORG = {
		fuzz("ORG",true)
	},
	OFFSET = {
		fuzz("OFFSET",true)
	},
	DATA = {
		fuzz("DATA",true)
	},
	CODE = {
		fuzz("CODE",true)
	},
	DB = {
		fuzz("DB",true)
	},
	ALLOC = {
		fuzz("ALLOC",true)
	},
	HASH = {
		"%#"
	},
	COLON = {
		":"
	},
	IDENT = {
		"[A-Za-z_][A-Za-z0-9_]*"
	},
}

for k,v in ipairs(TOKEN_PATTERNS.REGISTER) do
	TOKEN_PATTERNS.REGISTER[k] = fuzz(v,false,true)
end
for k,v in ipairs(TOKEN_PATTERNS.SEGMENT) do
	TOKEN_PATTERNS.SEGMENT[k] = fuzz(v,false,true)
end

local Instructions = {}
do
	local patterns, p0 = TOKEN_PATTERNS.INSTRUCTION, TOKEN_PATTERNS.INST_0
	for _, i in ipairs(CPULib.InstructionTable) do
		if i.OperandCount > 0 then
			table.insert(patterns, fuzz(i.Mnemonic, true, true))
		else
			table.insert(p0, fuzz(i.Mnemonic, true, true))
		end
		Instructions[i.Opcode] = i
		Instructions[i.Mnemonic] = i.Opcode
	end
end

local t = TOKEN_PATTERNS

local TOKEN_ORDER = {
	t.COMMENT,
	t.MULTI_COMMENT_START,
	t.MULTI_COMMENT_END,
	t.DATA,
	t.CODE,
	t.REGISTER,
	t.SEGMENT,
	t.INST_0,
	t.INSTRUCTION,
	t.DB,
	t.ALLOC,
	t.OFFSET,
	t.ORG,
	t.HASH,
	t.IDENT,
	t.OPAREN,
	t.CPAREN,
	t.OSQUARE,
	t.CSQUARE,
	t.STRING,
	t.LITERAL,
	t.COLON,
	t.PERIOD,
	t.COMMA,
	t.NUMBER,
	t.OP_ASSIGN,
	t.OP_EQ,
	t.OP_NEQ,
	t.OP_GT,
	t.OP_GTE,
	t.OP_LT,
	t.OP_LTE,
	t.OP_LAND,
	t.OP_LOR,
	t.OP_BAND,
	t.OP_BOR,
	t.OP_BXOR,
	t.OP_PLUS,
	t.OP_MINUS,
	t.OP_MULT,
	t.OP_DIV,
	t.OP_MOD,
}

do
	local reverse_tokens = {}
	for k,v in pairs(TOKEN_PATTERNS) do
		for ind,i in ipairs(TOKEN_ORDER) do
			if i == v then
				reverse_tokens[ind] = k
				break
			end
		end
	end
	for k,v in pairs(reverse_tokens) do
		TOKEN_PATTERNS[k] = v
	end
end

local HL_TOKEN_PATTERNS = {
	LABEL = {
		{"IDENT","COLON"},
	},
	MEMREG_SQ = {
		{"OSQUARE","REGISTER","CSQUARE"},
		{"OSQUARE","SEGMENT","CSQUARE"},
	},
	MEMREG_HASH = {
		{"HASH","REGISTER"},
		{"HASH","SEGMENT"},
	},
	SEGREG = {
		{"REGISTER","COLON","SEGMENT"},
		{"SEGMENT","COLON","REGISTER"},
		{"REGISTER","COLON","REGISTER"},
	},
	MEMREG_SEG = {
		{"SEGMENT","COLON","MEMREG_HASH"},
		{"REGISTER","COLON","MEMREG_HASH"},
		{"OSQUARE","SEGREG","CSQUARE"},
	},
	MEMCONST_SQ = {
		{"OSQUARE","CONST_SINGLE","CSQUARE"},
	},
	MEMCONST_HASH = {
		{"HASH","CONST_SINGLE"},
	},
	SEGCONST = {
		{"SEGMENT","COLON","CONST_SINGLE","OPERATOR","!BREAK!"},
		{"REGISTER","COLON","CONST_SINGLE","OPERATOR","!BREAK!"},
		{"SEGMENT","COLON","CONST_SINGLE"},
		{"REGISTER","COLON","CONST_SINGLE"},
	},
	MEMCONST_SEG = {
		{"SEGMENT","COLON","MEMREG_HASH"},
		{"REGISTER","COLON","MEMREG_HASH"},
		{"OSQUARE","SEGCONST","CSQUARE"},
	},
	INST_REGREG = {
		{"INSTRUCTION","REGISTERLIKE","COMMA","REGISTERLIKE"},
	},
	INST_REGCONST = {
		{"INSTRUCTION","REGISTERLIKE","COMMA","CONST_SINGLE","OPERATOR","!BREAK!"},
		{"INSTRUCTION","REGISTERLIKE","COMMA","CONST_SINGLE"},
	},
	INST_CONSTREG = {
		{"INSTRUCTION","CONST_SINGLE","COMMA","REGISTERLIKE"},
	},
	INST_REG = {
		{"INSTRUCTION","REGISTERLIKE","COMMA","!BREAK!"},
		{"INSTRUCTION","REGISTERLIKE"},
	},
	INST_CONST = {
		{"INSTRUCTION","!ANY!","COMMA","!BREAK!"},
		{"INSTRUCTION","CONST_SINGLE","OPERATOR","!BREAK!"},
		{"INSTRUCTION","CONST_SINGLE"},
	},
	INST_CONSTCONST = {
		{"INSTRUCTION","CONST_SINGLE","COMMA","CONST_SINGLE","OPERATOR","!BREAK!"},
		{"INSTRUCTION","CONST_SINGLE","COMMA","CONST_SINGLE"},
	},
	REGISTERLIKE = {
		{"SEGMENT","COLON","!BREAK!"},
		{"REGISTER","COLON","!BREAK!"},
		{"HASH","!BREAK!"},
		{"REGISTER"},
		{"SEGMENT"},
		{"MEMREG_SEG"},
		{"MEMREG_SQ"},
		{"MEMREG_HASH"},
		{"SEGREG"},
		{"MEMCONST_SEG"},
		{"MEMCONST_SQ"},
		{"MEMCONST_HASH"},
		{"SEGCONST"},
	},
	VALUE_GROUP = {
		{"INSTRUCTION","!BREAK!"},
		{"!PREV!","INSTRUCTION","!BREAK!"},
		{"ALLOC","IDENT","!BREAK!"},
		{"CONST_SINGLE","COMMA","CONST_SINGLE","OPERATOR","!BREAK!"},
		{"VALUE_GROUP","COMMA","CONST_SINGLE","OPERATOR","!BREAK!"},
		{"VALUE_GROUP","COMMA","CONST_SINGLE"},
		{"VALUE_GROUP","COMMA","CONST_MULTI"},
		{"CONST_SINGLE","COMMA","CONST_SINGLE"},
		{"CONST_MULTI","COMMA","CONST_SINGLE"},
		{"CONST_SINGLE","COMMA","CONST_MULTI"},
	},
	COMPLETE_VALUE_GROUP = {
		{"VALUE_GROUP","COMMA","!BREAK!"},
		{"VALUE_GROUP"},
	},
	CONST_SINGLE = {
		{"IDENT","COLON","!BREAK!"},
		-- We need to process the operator properly first, goofball.
		{"!ANY!","OP_[^bB].*","!BREAK!"},
		{"!ANY!","OPERATOR_BITWISE","!BREAK!"},
		{"LITERAL"},
		{"NUMBER"},
		{"IDENT"},
		{"EXPRESSION"}
	},
	OPERATOR_ASSIGN = {
		{"OPERATOR","OP_ASSIGN"},
		{"OP_ASSIGN"}
	},
	OPERATOR = {
		{"OP_[^bB].*"},
		{"OPERATOR_BITWISE"}
	},
	OPERATOR_BITWISE = {
		{"OP_BAND"},
		{"OP_BOR"},
		{"OP_BXOR"},
	},
	CONST_MULTI = { -- multibyte constant types
		{"STRING"},
	},
	STATIC_DB = {
		{"DB","!ANY!","OPERATOR","!BREAK!"},
		{"DB","!ANY!","COMMA","!BREAK!"},
		{"DB","COMPLETE_VALUE_GROUP"},
		{"DB","CONST_MULTI"},
		{"DB","CONST_SINGLE"}
	},
	ALLOC_COMPLETE = {
		{"ALLOC","CONST_SINGLE","OP_.*","!BREAK!"},
		{"ALLOC","CONST_SINGLE","OPERATOR*","!BREAK!"},
		{"ALLOC","CONST_SINGLE","COMMA","!BREAK!"},
		{"ALLOC","COMPLETE_VALUE_GROUP"},
		{"ALLOC","CONST_SINGLE"},
	},
	MULTI_COMMENT = {
		{"MULTI_COMMENT","MULTI_COMMENT_END","!BREAK!"},
		{"MULTI_COMMENT","!ANY!"},
		{"MULTI_COMMENT_START","!ANY!"}
	},
	FIN_MULTI_COMMENT = {
		{"MULTI_COMMENT","MULTI_COMMENT_END"},
		{"MULTI_COMMENT_START","MULTI_COMMENT_END"},
	},
	EXPRESSION = {
		{"CONST_SINGLE","OPERATOR","CONST_SINGLE"},
		{"EXPRESSION","OPERATOR","CONST_SINGLE"},
		{"CONST_SINGLE","OPERATOR","EXPRESSION"},
		{"EXPRESSION","OPERATOR","EXPRESSION"},
		{"OPAREN","CONST_SINGLE","OPERATOR","CONST_SINGLE","CPAREN"},
		{"OPAREN","EXPRESSION","OPERATOR","CONST_SINGLE","CPAREN"},
		{"OPAREN","EXPRESSION","OPERATOR","EXPRESSION","CPAREN"},
		{"OPAREN","CONST_SINGLE","OPERATOR","EXPRESSION","CPAREN"},
		{"OPAREN","CONST_SINGLE","CPAREN"},
		{"OPAREN","EXPRESSION","CPAREN"},
		{"!PREV!","NUMBER","!BREAK!"},
		{"!PREV!","IDENT","!BREAK!"},
		{"!PREV!","CONST_SINGLE","!BREAK!"},
		{"!PREV!","EXPRESSION","!BREAK!"},
		{"OP_MINUS","NUMBER"},
		{"OP_MINUS","IDENT"},
	},
	MACRO = {
		{"HASH","!NEWLINE!","!BREAK!"},
		{"MACRO","!NEWLINE!","!BREAK!"},
		{"HASH","REGISTER","!BREAK!"},
		{"HASH","SEGMENT","!BREAK!"},
		{"HASH","REGISTERLIKE","!BREAK!"},
		{"HASH","!ANY!"},
		{"MACRO","!ANY!"},
	},
	COMPLETE_MACRO = {
		{"MACRO","!NEWLINE!"}
	},
	COMPLETE_OFFSET = {
		{"OFFSET","CONST_SINGLE"}
	},
	COMPLETE_ORG = {
		{"ORG","CONST_SINGLE"}
	},
}

local h = HL_TOKEN_PATTERNS

local HL_TOKEN_ORDER = {
	h.MULTI_COMMENT,
	h.FIN_MULTI_COMMENT,
	h.LABEL,
	h.MEMREG_HASH,
	h.MEMREG_SQ,
	h.SEGREG,
	h.MEMREG_SEG,
	h.MEMCONST_HASH,
	h.MEMCONST_SQ,
	h.SEGCONST,
	h.MEMCONST_SEG,
	h.INST_REGCONST,
	h.INST_REGREG,
	h.INST_CONSTCONST,
	h.INST_CONSTREG,
	h.INST_REG,
	h.INST_CONST,
	h.REGISTERLIKE,
	h.EXPRESSION,
	h.OPERATOR_BITWISE,
	h.OPERATOR_ASSIGN,
	h.OPERATOR, -- general ops must go last because they will match the prev.
	h.CONST_MULTI,
	h.CONST_SINGLE,
	h.VALUE_GROUP,
	h.COMPLETE_VALUE_GROUP,
	h.STATIC_DB,
	h.ALLOC_COMPLETE,
	h.COMPLETE_OFFSET,
	h.COMPLETE_ORG,
	h.MACRO,
	h.COMPLETE_MACRO,
}

local errorTokens = {
	OPERATOR_ASSIGN = "Assignment cannot be done, variables not supported in this assembler.",
	OPERATOR_BITWISE = "Bitwise operators not supported at this time."
}

-- tokens that are allowed to exist after all work is complete

local whitelistTokens = {
	INST_0            = true,
	INST_REG          = true,
	INST_CONST        = true,
	INST_REGREG       = true,
	INST_REGCONST     = true,
	INST_CONSTREG     = true,
	INST_CONSTCONST   = true,
	FIN_MULTI_COMMENT = true,
	COMMENT           = true,
	LABEL             = true,
	STATIC_DB         = true,
	ALLOC_COMPLETE    = true,
	COMPLETE_MACRO    = true,
	COMPLETE_ORG      = true,
	["!NEWLINE!"]     = true,
	DATA              = true,
	CODE              = true,
}

local tokenErrorReason = {
	OPERATOR = "Operator had no neighboring values to combine into."
}

zasmTokenize = tinyToken.createTokenizer(TOKEN_PATTERNS,HL_TOKEN_PATTERNS,TOKEN_ORDER,HL_TOKEN_ORDER,errorTokens,tokenErrorReason)

local REGISTER = {
	"EAX","EBX","ECX","EDX","ESI","EDI","ESP","EBP", -- General Registers 1-8
	"CS","SS","DS","ES","GS","FS","KS","LS", -- Segments 9-16
	"M_EAX","M_EBX","M_ECX","M_EDX","M_ESI","M_EDI","M_ESP","M_EBP","M_CONST", -- Memory reads 17-25
	"S_EAX","S_EBX","S_ECX","S_EDX","S_ESI","S_EDI","S_ESP","S_EBP", -- General + Seg 26-33
	"C_EAX","C_EBX","C_ECX","C_EDX","C_ESI","C_EDI","C_ESP","C_EBP", -- General + Const (no syntax?) 34-42
	"S_CONST" -- Seg + Const 43
}

-- register but remapped to the way the ZCPU sees segments
local SEGMENT_REGISTER = {
	"CS","SS","DS","ES","GS","FS","KS","LS",
	"EAX","EBX","ECX","EDX","ESI","EDI","ESP","EBP",
}


for k,v in ipairs(REGISTER) do
	REGISTER[v] = k
end

for k,v in ipairs(SEGMENT_REGISTER) do
	SEGMENT_REGISTER[v] = k
end

local function encodeInstruction(instruction,reg1,reg2,seg1,seg2,fixed)
	if seg1 or seg2 then
		instruction = instruction + 1000
	end
	if seg1 and seg2 then
		instruction = instruction + 10000
	end
	if not reg2 then reg2 = 0 end
	local RM = reg1 and reg1+(reg2*10000) or nil
	local ret = {instruction,RM,seg1,seg2}
	local nret = {}
	for i=1,6,1 do
		if ret[i] then
			table.insert(nret,ret[i])
		end
	end
	return unpack(nret)
end

local unknown_ident_dependents = {}
local idents = {}
local ident_lookups = {}
setmetatable(idents,{
	__index = function(self,k)
		return rawget(ident_lookups,ident_lookups[k]) or ident_lookups[k]
	end
})
local OFFSET = 0
local dumpValueGroup

local function extractConst(const_token,parent_token,index,immediate)
	local t = const_token.t
	if t == "CONST_SINGLE" or t == "CONST_MULTI" then
		return extractConst(const_token.group[1],parent_token,index,immediate)
	end
	local value = const_token.v
	if not value then error("Invalid constant in token type "..tostring(t),2) end
	if t == "NUMBER" then
		if not index then
			return tonumber(value)
		end
		parent_token.buffer[index] = tonumber(value)
		return 1
	end
	if t == "IDENT" then
		local ident = idents[value]
		if ident then
			if type(ident) ~= "number" then
				-- print(ident.t)
				if ident.t == "COMPLETE_VALUE_GROUP" then
					return dumpValueGroup(ident,parent_token,nil,immediate)
				end
				return extractConst(ident,parent_token,index,immediate) -- ident may be another token type
			end
			if not index then
				return ident
			end
			parent_token.buffer[index] = ident
		else
			-- print("Unresolved",value,immediate)
			if not index then return end
			if immediate then error("Ident ("..const_token.v..") is undefined!",2) end
			if not unknown_ident_dependents[value] then
				unknown_ident_dependents[value] = {}
			end
			table.insert(unknown_ident_dependents[value],{const_token,parent_token,index,OFFSET})
		end
		return 1
	end
	if t == "LITERAL" then
		local str = const_token.v
		local len = (#str)-1
		local num = 0
		for i=2,len do
			num = bit.lshift(num,8) -- useless on first but will work, trust.
			num = bit.bor(num,string.byte(str,i))
		end
		if not index then
			return num
		end
		parent_token.buffer[index] = num
		return 1
	end
	if t == "STRING" then
		local str = const_token.v
		local len = (#str)-1
		local dest = parent_token.buffer
		if not index then
			dest = {}
		end
		-- todo: escaped characters I guess. I wonder if there's an ISO standard about them.
		for i=2,len,1 do
			dest[index+(i-2)] = string.byte(str,i)
		end
		if not index then
			return dest
		end
		return len-1 -- to account for first quotation mark, which we skip with i=2.
	end
	if t == "EXPRESSION" then
		-- binary operators need conversion or removal
		local v = CompileString("return "..const_token.v)
		if v then
			setfenv(v,idents)
			local succ
			succ,v = pcall(v)
			if not succ then
				if string.match(v,"a nil value") then
					local required_labels = {}
					for match in string.gmatch(const_token.v,"[A-Za-z_][A-Za-z0-9_]*") do
						table.insert(required_labels,match)
					end
					local function expr()
						for _,label in ipairs(required_labels) do
							if not idents[label] then return end
						end
						return extractConst(const_token,parent_token,index,immediate)
					end
					for _,label in ipairs(required_labels) do
						if not unknown_ident_dependents[label] then
							unknown_ident_dependents[label] = {}
						end
						table.insert(unknown_ident_dependents[label],expr)
					end
				else
					error("Error in expression execution ["..v.."]",0)
				end
			end
		else
			error("Invalid expression ["..const_token.v.."]",0)
		end
		if type(v) == "boolean" then
			v = v and 1 or 0
		end
		if not index then
			return v
		end
		parent_token.buffer[index] = v
		return 1
	end
end


local DPTR = 0
local OFFSET = 0
local OUTPUT_BUFFER = {}

local instruction_encoders = {}

local keyword_handlers = {}

local function determineRegister(token)
	local toptoken = token.t
	local reg_group = token.group and token.group[1] or toptoken
	local true_type = reg_group.t or toptoken

	if true_type == "REGISTER" or true_type == "SEGMENT" then
		return REGISTER[reg_group.vup]
	end
	if true_type == "MEMREG_SEG" then
		if reg_group.group[1].t == "SEGMENT" or reg_group.group[1].t == "REGISTER" then -- SEG:#REG
			return REGISTER["M_"..reg_group.group[1].vup],REGISTER[reg_group.group[3].group[2].vup]
		end
		if reg_group.group[1].t == "OSQUARE" then -- [SEG:REG]
			local segreg = reg_group.group[2]
			return REGISTER["M_"..segreg.group[3].vup],REGISTER[segreg.group[1].vup]
		end
	end
	if true_type == "MEMREG_SQ" or true_type == "MEMREG_HASH" then
		local reg = REGISTER["M_"..reg_group.group[2].vup]
		return REGISTER["M_"..reg_group.group[2].vup]
	end

	if true_type == "MEMCONST_SEG" then
		if reg_group.group[1].t == "SEGMENT" or reg_group.group[1].t == "REGISTER" then -- SEG:#CONST
			return REGISTER["M_CONST"],REGISTER[reg_group.group[3].group[2].vup],reg_group.group[4]
		end
		if reg_group.group[1].t == "OSQUARE" then -- [SEG:CONST]
			local segreg = reg_group.group[2]
			return REGISTER["M_CONST"],REGISTER[segreg.group[1].vup],segreg.group[3]
		end
	end
	if true_type == "MEMCONST_SQ" or true_type == "MEMCONST_HASH" then
		return REGISTER["M_CONST"],nil,reg_group.group[2]
	end
end

function instruction_encoders.INST_0(token)
	local bytes = {encodeInstruction(Instructions[token.vup])}
	-- print(bytes[1])
	return bytes,1
end

function instruction_encoders.INST_REG(token)
	local r1,seg1,const1 = determineRegister(token.group[2])
	local bytes = {encodeInstruction(Instructions[token.group[1].vup],r1)}
	local size = #bytes
	if const1 then
		size = size + extractConst(const1,token,size+1)
	end
	return bytes,size
end

function instruction_encoders.INST_REGREG(token)
	local r1,seg1,const1 = determineRegister(token.group[2])
	local r2,seg2,const2 = determineRegister(token.group[4])
	local bytes = {encodeInstruction(Instructions[token.group[1].vup],r1,r2,seg1,seg2)}
	local size = #bytes
	if const1 then
		size = size + extractConst(const1,token,size+1)
	end
	if const2 then
		size = size + extractConst(const2,token,size+1)
	end
	return bytes,size
end

function instruction_encoders.INST_REGCONST(token)
	local r1,seg1,const1 = determineRegister(token.group[2])
	local bytes = {encodeInstruction(Instructions[token.group[1].vup],r1,0,seg1)}
	local size = #bytes
	if const1 then
		size = size + extractConst(const1,token,size+1)
	end
	size = size + extractConst(token.group[4],token,size+1)
	return bytes,size
end

function instruction_encoders.INST_CONSTREG(token)
	local r2,seg2,const2 = determineRegister(token.group[4])
	local bytes = {encodeInstruction(Instructions[token.group[1].vup],0,r2,nil,seg2)}
	local size = #bytes
	if const2 then
		size = size + extractConst(const2,token,size+1)
	end
	size = size + extractConst(token.group[2],token,size+1)
	return bytes,size
end

function instruction_encoders.INST_CONST(token)
	local bytes = {encodeInstruction(Instructions[token.group[1].vup],0)}
	return bytes,#bytes+extractConst(token.group[2],token,3)
end

function instruction_encoders.INST_CONSTCONST(token)
	local bytes = {encodeInstruction(Instructions[token.group[1].vup],0,0)}
	return bytes,#bytes+extractConst(token.group[2],token,3)+extractConst(token.group[4],token,4)
end

-- forward declaration
dumpValueGroup = function(token,parentToken,tokens_only,immediate)
	if token.t ~= "COMPLETE_VALUE_GROUP" then
		tokenError("Attempting to extract an incomplete value group or non value group",token)
	end
	local traversed = {}
	local curtoken = token.group[1]
	local const_tokens = {}
	while(true) do
		if not curtoken or not curtoken.group or not curtoken.group[1] then
			break
		end
		if traversed[curtoken] then
			tokenError("Recursive traversal in value group.",token)
			return
		end
		if curtoken.t == "VALUE_GROUP" then
			table.insert(const_tokens,1,curtoken.group[3]) -- assuming const_single or const_multi
			curtoken = curtoken.group[1]
			goto skip
		end
		if curtoken.t == "CONST_SINGLE" then
			table.insert(const_tokens,1,curtoken)
			traversed[curtoken] = true
			curtoken = curtoken.group[1]
			goto skip
		end
		if curtoken.t == "CONST_MULTI" then
			table.insert(const_tokens,1,curtoken)
			traversed[curtoken] = true
			curtoken = curtoken.group[1]
			goto skip
		end
		::skip::
	end
	local dptr = 1
	if tokens_only then
		return const_tokens
	end
	for ind,const in ipairs(const_tokens) do
		dptr = dptr + extractConst(const,parentToken,dptr,immediate)
	end
	return dptr-1
end

local function defineLabel(name,value,token)
	if idents[name] then
		if token then
			error("Attempted to redefine label ("..name..")",0)
		end
		error("Attempted to redefine label ("..name..")",2)
	end
	print("Defined",name)
	idents[name] = value
	if unknown_ident_dependents[name] then
		for _,unk in ipairs(unknown_ident_dependents[name]) do
			if type(unk) == "function" then
				unk(value)
			else
				unk[2].buffer[unk[3]] = value
			end
		end
		unknown_ident_dependents[name] = nil
	end
end

function keyword_handlers.CODE(token)
	defineLabel("_code",DPTR + OFFSET,token)
end

function keyword_handlers.DATA(token)
	token.DPTR = DPTR
	token.buffer = {encodeInstruction(Instructions["JMP"],0)}
	token.size = #token.buffer+extractConst({
		t = "IDENT",
		v = "_code",
		vup = "_CODE",
		vlow = "_code",
	},token,#token.buffer+1)
	defineLabel("_data",DPTR + OFFSET + token.size,token) -- also define a label for data, why not.
	DPTR = DPTR + token.size
end

function keyword_handlers.LABEL(token)
	local name = token.group[1].v
	defineLabel(name,DPTR + OFFSET,token)
end

function keyword_handlers.STATIC_DB(token)
	token.buffer = {}
	token.DPTR = DPTR
	local size = 0
	if token.group[2].t == "COMPLETE_VALUE_GROUP" then
		size = dumpValueGroup(token.group[2],token)
	else
		size = extractConst(token.group[2],token,1)
	end
	return token.buffer,size
end

function keyword_handlers.COMPLETE_OFFSET(token)
	OFFSET = extractConst(token.group[2])
	-- print(OFFSET)
	if OFFSET == nil then
		error("Invalid offset generated from constant ["..token.group[2].v)
	end
end

function keyword_handlers.COMPLETE_ORG(token)
	DPTR = extractConst(token.group[2])
	-- print(OFFSET)
	if OFFSET == nil then
		error("Invalid dptr generated from constant ["..token.group[2].v)
	end
end

function keyword_handlers.ALLOC_COMPLETE(token)
	token.buffer = {}
	token.DPTR = DPTR
	if token.group[2].t == "COMPLETE_VALUE_GROUP" then
		local tokens = dumpValueGroup(token.group[2],token,true)
		local tlen = #tokens
		if smallConstTMatch(tokens,{"IDENT","!ANY!"}) then
			defineLabel(tokens[1].group[1].v,DPTR+OFFSET,token)
			local s = extractConst(tokens[2],token,1)
			return token.buffer,s
		end
		if smallConstTMatch(tokens,{"IDENT","!ANY!","NUMBER"}) then
			defineLabel(tokens[1].group[1].v,DPTR+OFFSET,token)
			local reps = extractConst(tokens[3],token)
			local s = extractConst(tokens[2],token,1)
			local dbuffer = token.buffer
			token.buffer = {}
			for i=0,reps*s-1,s do
				for j=1,s,1 do
					token.buffer[i+j]=dbuffer[j]
				end
			end
			return token.buffer,#token.buffer
		end
		if smallConstTMatch(tokens,{"!ANY!","NUMBER"}) then
			extractConst(tokens[2],token,1)
			local reps = token.buffer[1]
			local s = extractConst(tokens[1],token,1)
			local dbuffer = token.buffer
			token.buffer = {}
			for i=0,reps*s-1,s do
				for j=1,s,1 do
					token.buffer[i+j]=dbuffer[j]
				end
			end
			return token.buffer,#token.buffer
		end
		error("Invalid valuegroup.",2)
	end
	if token.group[2].group[1].t == "IDENT" then
		defineLabel(token.group[2].group[1].v,DPTR,token)
		token.buffer[1] = 0
		return token.buffer,1
	end
	if token.group[2].group[1].t == "NUMBER" or token.group[2].group[1].t == "LITERAL" then
		local n = extractConst(token.group[2],token)
		for i=n,1,-1 do
			table.insert(token.buffer,0)
		end
		return token.buffer,n
	else
		-- just assume it's a const_single or something idk
		local n = extractConst(token.group[2],token)
		for i=n,1,-1 do
			table.insert(token.buffer,0)
		end
		return token.buffer,n
	end
end

local macros = {}
local pragmas = {}

function macros.PRAGMA(ll_tokens,hl_tokens)
	local arg1 = ll_tokens[1].v
	if pragmas[arg1] then
		return pragmas[arg1](ll_tokens,hl_tokens)
	end
end

-- only generate them if desired.
function pragmas.GenerateInstructionDefines(ll_tokens,hl_tokens)
	local desired = ll_tokens[2].v
	if smatch(desired,fuzz("instructionNamesUpper")) then
		local tokstr = ""
		local ptrstr = ""
		local curptr = 0
		for ind,v in ipairs(Instructions) do
			ptrstr = ptrstr .. curptr .. ","
			defineLabel("__ZCOMP_INST_NAMES_UPPER_"..v[4]:upper().."_PTR",curptr)
			curptr = curptr + #v[4]
			tokstr = tokstr .. "\"" .. v[4]:upper() .. "\"" .. ",0,"
			defineLabel("__ZCOMP_INST_NAMES_UPPER_"..v[4]:upper(),zasmTokenize("\""..v[4]:upper().."\"")[1])
		end
		defineLabel("__ZCOMP_INST_NAMES_UPPER",zasmTokenize(tokstr:sub(1,-2))[1])
		defineLabel("__ZCOMP_INST_NAMES_UPPER_PTRS",zasmTokenize(ptrstr:sub(1,-2))[1])
		return
	end
	if smatch(desired,fuzz("instructionNamesLower")) then
		local tokstr = ""
		local ptrstr = ""
		local curptr = 0
		for ind,v in ipairs(Instructions) do
			ptrstr = ptrstr .. curptr .. ","
			defineLabel("__ZCOMP_INST_NAMES_LOWER_"..v[4]:upper().."_PTR",curptr)
			curptr = curptr + #v[4]
			tokstr = tokstr .. "\"" .. v[4]:lower() .. "\"" .. ",0,"
			defineLabel("__ZCOMP_INST_NAMES_LOWER_"..v[4]:upper(),zasmTokenize("\""..v[4]:lower().."\"")[1])
		end
		defineLabel("__ZCOMP_INST_NAMES_LOWER",zasmTokenize(tokstr:sub(1,-2))[1])
		defineLabel("__ZCOMP_INST_NAMES_LOWER_PTRS",zasmTokenize(ptrstr:sub(1,-2))[1])
		return
	end
	if smatch(desired,fuzz("opCount")) then
		local tokstr = ""
		local ptrstr = ""
		for ind,v in ipairs(Instructions) do
			tokstr = tokstr .. v[2] .. ","
			defineLabel("__ZCOMP_INST_OPERAND_COUNTS_"..v[4]:upper(),v[2])
		end
		defineLabel("__ZCOMP_INST_OPERAND_COUNTS",zasmTokenize(tokstr:sub(1,-2))[1])
		return
	end
	if smatch(desired,fuzz("registerNamesUpper")) then
		local tokstr = ""
		local ptrstr = ""
		local curptr = 0
		for ind,v in ipairs(REGISTER) do
			ptrstr = ptrstr .. #tokstr .. ","
			defineLabel("__ZCOMP_REG_NAMES_UPPER_"..v:upper().."_PTR",curptr)
			curptr = curptr + #v
			tokstr = tokstr .. "\"" .. v:upper() .. "\"" .. ",0,"
			defineLabel("__ZCOMP_REG_NAMES_UPPER_"..v:upper(),zasmTokenize("\""..v:upper().."\"")[1])
		end
		defineLabel("__ZCOMP_REG_NAMES_UPPER",zasmTokenize(tokstr:sub(1,-2))[1])
		defineLabel("__ZCOMP_REG_NAMES_UPPER_PTRS",zasmTokenize(ptrstr:sub(1,-2))[1])
		return
	end
	if smatch(desired,fuzz("registerNamesLower")) then
		local tokstr = ""
		local ptrstr = ""
		local curptr = 0
		for ind,v in ipairs(REGISTER) do
			ptrstr = ptrstr .. #tokstr .. ","
			defineLabel("__ZCOMP_REG_NAMES_LOWER_"..v:upper().."_PTR",curptr)
			curptr = curptr + #v
			tokstr = tokstr .. "\"" .. v:lower() .. "\"" .. ",0,"
			defineLabel("__ZCOMP_REG_NAMES_LOWER_"..v:upper(),zasmTokenize("\""..v:lower().."\"")[1])
		end
		defineLabel("__ZCOMP_REG_NAMES_LOWER",zasmTokenize(tokstr:sub(1,-2))[1])
		defineLabel("__ZCOMP_REG_NAMES_LOWER_PTRS",zasmTokenize(ptrstr:sub(1,-2))[1])
		return
	end
	if smatch(desired,fuzz("segmentRegisterNamesUpper")) then
		local tokstr = ""
		local ptrstr = ""
		local curptr = 0
		for ind,v in ipairs(SEGMENT_REGISTER) do
			ptrstr = ptrstr .. #tokstr .. ","
			defineLabel("__ZCOMP_SEGREG_NAMES_UPPER_"..v[4]:upper().."_PTR",curptr)
			curptr = curptr + #v
			tokstr = tokstr .. "\"" .. v:upper() .. "\"" .. ",0,"
			defineLabel("__ZCOMP_SEGREG_NAMES_UPPER_"..v:upper(),zasmTokenize("\""..v:upper().."\"")[1])
		end
		defineLabel("__ZCOMP_SEGREG_NAMES_UPPER",zasmTokenize(tokstr:sub(1,-2))[1])
		defineLabel("__ZCOMP_SEGREG_NAMES_UPPER_PTRS",zasmTokenize(ptrstr:sub(1,-2))[1])
		return
	end
	if smatch(desired,fuzz("segmentRegisterNamesLower")) then
		local tokstr = ""
		local ptrstr = ""
		local curptr = 0
		for ind,v in ipairs(SEGMENT_REGISTER) do
			ptrstr = ptrstr .. #tokstr .. ","
			defineLabel("__ZCOMP_SEGREG_NAMES_LOWER_"..v[4]:upper().."_PTR",curptr)
			tokstr = tokstr .. "\"" .. v:lower() .. "\"" .. ",0,"
			defineLabel("__ZCOMP_SEGREG_NAMES_LOWER_"..v:upper(),zasmTokenize("\""..v:lower().."\"")[1])
		end
		defineLabel("__ZCOMP_SEGREG_NAMES_LOWER",zasmTokenize(tokstr:sub(1,-2))[1])
		defineLabel("__ZCOMP_SEGREG_NAMES_LOWER_PTRS",zasmTokenize(ptrstr:sub(1,-2))[1])
		return
	end
end

_G.idents = idents

function macros.DEFINE(ll_tokens,hl_tokens)
	local arg1 = ll_tokens[1]
	local arg2 = ll_tokens[2]
	-- print(arg1.v,arg1.t,arg2.v,arg2.t)
	if arg2.t == "NUMBER" then
		ident_lookups[arg1.v] = tonumber(arg2.v)
		goto solved
	end
	if arg2.t == "IDENT" then
		ident_lookups[arg1.v] = arg2.v
		goto solved
	end
	if arg2.t == "CONST_SINGLE" or arg2.t == "CONST_MULTI" then
		ident_lookups[arg1.v] = arg2
		goto solved
	end
	::solved::
	if unknown_ident_dependents[arg1.v] then
		for _,unk in ipairs(unknown_ident_dependents[arg1.v]) do
			-- print("dependants")
			unk[2].buffer[unk[3]] = extractConst(arg2,nil,nil)
		end
	end
end

function keyword_handlers.COMPLETE_MACRO(token)
	local args = {}
	for str in string.gmatch(token.v,"[^%s#]+") do
		table.insert(args,str)
	end
	local fn = string.upper(table.remove(args,1))
	if not macros[fn] then
		zasmTokenize.tokenError("Invalid Macro ("..fn..")",token)
		return
	end
	local tokens,ll_tokens = zasmTokenize(table.concat(args," "),true)
	local succ,err = pcall(macros[fn],ll_tokens,tokens)
	if not succ then
		zasmTokenize.tokenError("Macro Error:"..err,token)
	end
end

function ZCAssemble(str,fname,writeByte,successCB,errorCB)
	zasmTokenize.errorCallback = errorCB
	zasmTokenize.errFname = fname
	local benchtime = SysTime()
	local tokens = zasmTokenize(str)
	unknown_ident_dependents = {}
	idents = {}
	ident_lookups = {}
	setmetatable(idents,{
		__index = function(self,k)
			return rawget(ident_lookups,ident_lookups[k]) or ident_lookups[k]
		end
	})
	_idents = idents
	_ident_lookups = ident_lookups
	_ident_dependents = unknown_ident_dependents
	_tokens = tokens
	DPTR = 0
	OFFSET = 0
	OUTPUT_BUFFER = {}

	-- fixed size allocations, pre-buffer size and constant determination
	for ind,token in ipairs(tokens) do
		local t = token.t
		local b,s
		-- print(token.line,token.t,token.v)
		if not whitelistTokens[t] then
			zasmTokenize.tokenError(tokenErrorReason[t] or "Syntax error. Token of type "..(token.t or "undefined").." was left over.",token)
			break
		end
		if keyword_handlers[t] then
			b,s = keyword_handlers[t](token)
			goto skip
		end
		if instruction_encoders[t] then
			token.buffer = {}
			token.size = 0
			local succ
			succ,b,s = pcall(instruction_encoders[t],token)
			if not succ then 
				zasmTokenize.tokenError(b,token)
				break
			end
		end
		::skip::
		if b then
			token.DPTR = DPTR
			token.size = s
			for ind,i in ipairs(b) do
				token.buffer[ind]=i
			end
			DPTR = DPTR + token.size
		end
	end
	if zasmTokenize.error then return 0,{},{},{},{},{},{},{},{} end
	if next(unknown_ident_dependents) then
		local n,token = next(unknown_ident_dependents)
		if type(token) == "function" then
			zasmTokenize.tokenError(n.." is used in an expression but was never defined",{s=1,line=1})
		else
			zasmTokenize.tokenError(token[1][2].t.." has an undefined ident("..n..")",token[1][1])
		end
	end
	if zasmTokenize.error then return 0,{},{},{},{},{},{},{},{} end
	for _,token in ipairs(tokens) do
		-- print(token.t,token.v)
		if token.buffer then
			-- print("output ",token.t)
			local dptr = token.DPTR
			if token.size ~= #token.buffer then
				_missingToken = token
				zasmTokenize.tokenError("Missing values in "..token.t.." (".._..")",token)
				break
			end
			for ind,byte in pairs(token.buffer) do 
				-- print(dptr+ind,byte)
				-- sleep(1)
				if not byte then
					zasmTokenize.tokenError(token.t.."(",_,")".." at pos "..dptr+ind.." has an undefined/invalid constant",0)
					break
				end
				OUTPUT_BUFFER[dptr+ind] = byte
			end
		end
	end
	if zasmTokenize.error then return 0,{},{},{},{},{},{},{},{} end

	local highest = 0
	for ind,v in pairs(OUTPUT_BUFFER) do
		-- find end point rq to fill any gaps in program with padding 0's
		if ind > highest then
			highest = ind
		end
	end
	for i=1,highest do
		if not OUTPUT_BUFFER[i] then
			OUTPUT_BUFFER[i] = 0
		end
	end
	local size = 0
	for ind,i in ipairs(OUTPUT_BUFFER) do
		size = size + 1
		writeByte(nil,ind-1,i)
	end
	local warns = {}
	local MemoryVariableByIndex = {}
	local MemoryVariableByName = {}
	local Labels = {}
	local PositionByPointer = {}
	local PointersByLine = {} 
	for k,v in pairs(idents) do
		if type(v) == "number" then
			Labels[k] = {
				Pointer = v
			}
		end
	end
	print((SysTime()-benchtime)*1000)
	-- return these to the GC
	unknown_ident_dependents = {}
	idents = {}
	ident_lookups = {}
	DPTR = 0
	OFFSET = 0
	OUTPUT_BUFFER = {}
	zasmTokenize.errorCallback = nil
	successCB(warns)
	-- CPULib.Debugger.MemoryVariableByIndex,
    -- CPULib.Debugger.MemoryVariableByName,
    -- CPULib.Debugger.Labels,
    -- CPULib.Debugger.PositionByPointer,
    -- CPULib.Debugger.PointersByLine 
	return size,warns,MemoryVariableByIndex,MemoryVariableByName,Labels,PositionByPointer,PointersByLine
end