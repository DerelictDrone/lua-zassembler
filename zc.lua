-- local starttime = os.epoch("local")
-- tokenizer
local smatch = string.match

-- case insensitivizer
local function fuzz(str,barrier,paren)
	local len = #str
	local newpat = ""
	for i=1,len,1 do
		local char = str:sub(i,i)
		newpat = newpat .. "["..char:upper()..char:lower().."]"
	end
	if paren then
		newpat = "("..newpat..")"
	end
	newpat =  newpat..(barrier and "%s" or "")
	return newpat
end

local errorCallback
local errFname
--error wrapper
local function tokenError(msg,token)
	token.line = token.line + 2
	local msg = string.format("[line: %d column: %d] %s",token.line,token.s,msg)
	if errorCallback then
		errorCallback(msg,{
			Line = token.line,
			Col = token.s,
			File = errFname
		})
	else
		error(msg,0)
	end
end

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
	STRING = {"\"[^\n]*\"","'[^\n]*'"},
	LITERAL = {"$'[^']?[^']?[^']?[^']?'"},
	NUMBER = {
		"0[xX]%x+", -- hexadecimal
		"-?%d+%.?%d*e[+-]?%d*", -- scientific
		"-?%d+%.?%d*", -- decimal
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
		{"SEGMENT","COLON","MEMCONST_HASH"},
		{"REGISTER","COLON","MEMCONST_HASH"},
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
		{"INSTRUCTION","CONST_SINGLE"},
	},
	INST_CONSTCONST = {
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
		{"ALLOC","IDENT","!BREAK!"},
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
		{"OPAREN","EXPRESSION","CPAREN"}
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
	h.OPERATOR_BITWISE,
	h.OPERATOR_ASSIGN,
	h.OPERATOR, -- general ops must go last because they will match the prev.
	h.CONST_MULTI,
	h.CONST_SINGLE,
	h.EXPRESSION,
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
	OPERATOR_ASSIGN = "Assignment cannot be done, as there are no variables in this assembler.",
	OPERATOR_BITWISE = "Bitwise operators not supported at this time."
}

do
local function getAllTokenMatches(filter)
	local matches = {}
	for ind,patterns in ipairs(HL_TOKEN_ORDER) do
		if smatch(HL_TOKEN_PATTERNS[ind],filter) then
			table.insert(matches,HL_TOKEN_PATTERNS[ind])
		end
	end
	for ind,patterns in ipairs(TOKEN_ORDER) do
		if smatch(TOKEN_PATTERNS[ind],filter) then
			table.insert(matches,TOKEN_PATTERNS[ind])
		end
	end
	return matches
end
local reverse_table = {}
	for k,v in pairs(HL_TOKEN_PATTERNS) do
		for ind,i in ipairs(HL_TOKEN_ORDER) do
			if i == v then
				reverse_table[ind] = k
				break
			end
		end
	end
	for k,v in pairs(reverse_table) do
		HL_TOKEN_PATTERNS[k] = v
	end
	local present_tokens = {}
	local modified = false
	for tname,hl_token in ipairs(HL_TOKEN_ORDER) do
		-- apply start and end to every pattern token (this saves time I swear)
		::start_over::
		modified = false
		present_tokens = {}
		for _,pattern in ipairs(hl_token) do
			for ind,token_type in ipairs(pattern) do
				-- if string.sub(token_type,1,1) == "!" then
				-- 	break
				-- end
				if smatch(token_type,"[%.%*]+") then
					local f = getAllTokenMatches(token_type)
					modified = true
					local r = table.remove(hl_token,_)
					for find,i in ipairs(f) do
						local t = {}
						-- generate a copy of the table but with the filter replaced by the matched token
						for k,v in ipairs(r) do
							if k == ind then
								t[k] = i
							else
								t[k] = v
							end
						end
						table.insert(hl_token,_,t)
					end
					break
				end
				-- generate a list of already known tokens
				-- we can use this list to do a single hash lookup
				-- and skip the expensive matches
				present_tokens[token_type] = true
				-- pattern[ind] = "^"..token_type.."$"
			end
			if modified then break end
		end
		if modified then goto start_over end
		for k,v in pairs(present_tokens) do
			if k == "!ANY!" then
				hl_token.required = true
				break
			end
		end
		hl_token.present_tokens = present_tokens
	end
end
local Instructions = {}
do
	local unsortedInstructions = {}
	local files = file.Find("wire/client/zc_inst/*.lua","LUA")
	-- print("Files discovered: ",#files)
	for _,i in ipairs(files) do
		local fname = "wire/client/zc_inst/"..i
		-- print(_,i,"\n",fname)
		AddCSLuaFile(fname)
		local p = include(fname)
		for _,i in ipairs(p) do
			table.insert(unsortedInstructions,i)
		end
	end
	local patterns,p0 = TOKEN_PATTERNS.INSTRUCTION,TOKEN_PATTERNS.INST_0
	for _,i in ipairs(unsortedInstructions) do
		if i[2] > 0 then 
			table.insert(patterns,fuzz(i[4],true,true))
		else
			table.insert(p0,fuzz(i[4],true,true))
		end
		Instructions[i[1]] = i
		Instructions[i[4]] = i[1]
	end
end

local function getToken(str)
	str = str
	for ind,patternset in ipairs(TOKEN_ORDER) do
		for _,pattern in ipairs(patternset) do
			local s,res,e,e2 = str:match("^%s*()("..pattern..")()")
			if res then
				if type(e) == "string" then
					res = e
					e = e2
				end
				return {
					t = TOKEN_PATTERNS[ind],
					v = res,
					vup = res:upper(),
					vlow = res:lower(),
					s=s,e=e,
				}
			end
		end
	end
end

local function zasmTokenize(str,split)
	local s,e
	local tokenstack = {}
	local lines = 0
	for word in string.gmatch(str,"[^\n]+") do
		lines = lines + 1
		::reword::
		s,e = 1,#word+1
		local t = getToken(word)
		if t then
			table.insert(tokenstack,t)
			t.line = lines
			if t.e < e then
				word = string.sub(word,t.e,e)
				goto reword
			end
		end
		table.insert(tokenstack,{
			t = "!NEWLINE!",
			v = "\n",
			vup = "\n",
			vlow = "\n",
			s=s,e=e,
		})
	end
	local ll_tokens = {}
	if split then
		for ind,i in ipairs(tokenstack) do
			ll_tokens[ind] = i
		end
	end
	local cur_token = 0
	local iterations = 0
	local target = #tokenstack -- if we have not at LEAST performed this many operations, we should double back to make sure nothing was missed.
	while(true) do
		for nind,patterns in ipairs(HL_TOKEN_ORDER) do 
			local broken = false
			do
				local checked_token = tokenstack[cur_token+1]
				if checked_token and not patterns.present_tokens[checked_token.t] and not patterns.required then
					goto skip
				end
			end
			for _,pattern in ipairs(patterns) do
				local match = true
				for ind,token in ipairs(pattern) do
					local grabbed_token = tokenstack[cur_token+ind]
					if token == "!BREAK!" then
						-- antipatterns may end in !BREAK!
						-- to end evaluation early
						match = false
						broken = true
						break
					end
					if not grabbed_token or not patterns.present_tokens[grabbed_token.t] or (token ~= "!ANY!" and token ~= grabbed_token.t) then
						match = false
						break
					end
				end
				if broken then break end
				if match then
					local hl_token = {
						t = HL_TOKEN_PATTERNS[nind],
						group = {},
						vup = "",
						v = "",
						vlow = "",
					}
					for i=cur_token+1,cur_token+#pattern do
						local grabbed_token = table.remove(tokenstack,cur_token+1)
						hl_token.v = hl_token.v .. ' ' .. grabbed_token.v
						table.insert(hl_token.group,grabbed_token)
					end
					hl_token.line = hl_token.group[1].line
					hl_token.s = hl_token.group[1].s
					hl_token.vup = hl_token.v:upper()
					hl_token.vlow = hl_token.v:lower()
					if errorTokens[hl_token.t] then
						tokenError(errorTokens[hl_token.t],hl_token)
					end
					table.insert(tokenstack,cur_token+1,hl_token)
					cur_token = 0
					target = target + 16 -- a successful token transformation, request two more iterations for the distillation
					break
				end
			end
			::skip::
		end
		cur_token = cur_token + 1
		iterations = iterations + 1
		if not tokenstack[cur_token] then
			if iterations > target then
				break
			end
			cur_token = 0
		end
	end
	if split then
		return tokenstack,ll_tokens
	end
	return tokenstack
end

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
		if idents[const_token.v] then
			if not index then
				return idents[value]
			end
			parent_token.buffer[index] = idents[value]
		else
			print("Unresolved",value,immediate)
			if not index then return end
			if immediate then error("Ident ("..const_token.v..") is undefined!",0) end
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
			num = bit.blshift(num,8) -- useless on first but will work, trust.
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
		local v = load("return "..const_token.v)
		if v then
			setfenv(v,idents)
			local succ
			succ,v = pcall(v)
			if not succ then
				tokenError("Error in expression execution ["..v.."]",const_token)
			end
		else
			tokenError("Invalid expression ["..const_token.v.."]",const_token)
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
		size = size + extractConst(const1,token,size+1,true)
	end
	return bytes,size
end

function instruction_encoders.INST_REGREG(token)
	local r1,seg1,const1 = determineRegister(token.group[2])
	local r2,seg2,const2 = determineRegister(token.group[4])
	local bytes = {encodeInstruction(Instructions[token.group[1].vup],r1,r2,seg1,seg2)}
	local size = #bytes
	if const1 then
		size = size + extractConst(const1,token,size+1,true)
	end
	if const2 then
		size = size + extractConst(const2,token,size+1,true)
	end
	return bytes,size
end

function instruction_encoders.INST_REGCONST(token)
	local r1,seg1,const1 = determineRegister(token.group[2])
	local bytes = {encodeInstruction(Instructions[token.group[1].vup],r1,0,seg1)}
	local size = #bytes
	if const1 then
		size = size + extractConst(const1,token,size+1,true)
	end
	size = size + extractConst(token.group[4],token,size+1,true)
	return bytes,size
end

function instruction_encoders.INST_CONSTREG(token)
	local r2,seg2,const2 = determineRegister(token.group[4])
	local bytes = {encodeInstruction(Instructions[token.group[1].vup],0,r2,nil,seg2)}
	local size = #bytes
	if const2 then
		size = size + extractConst(const2,token,size+1,true)
	end
	size = size + extractConst(token.group[2],token,size+1,true)
	return bytes,size
end

function instruction_encoders.INST_CONST(token)
	local bytes = {encodeInstruction(Instructions[token.group[1].vup],0)}
	return bytes,#bytes+extractConst(token.group[2],token,3,true)
end

function instruction_encoders.INST_CONSTCONST(token)
	local bytes = {encodeInstruction(Instructions[token.group[1].vup],0,0)}
	return bytes,#bytes+extractConst(token.group[2],token,3,true)+extractConst(token.group[4],token,4,true)
end

local function dumpValueGroup(token,parentToken,tokens_only)
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
		dptr = dptr + extractConst(const,parentToken,dptr)
	end
end

local function defineLabel(name,value,token)
	if idents[name] then
		if token then
			tokenError("Attempted to redefine label ("..name..")",token)
		end
		error("Attempted to redefine label ("..name..")",2)
	end
	idents[name] = value
	if unknown_ident_dependents[name] then
		for _,unk in ipairs(unknown_ident_dependents[name]) do
			unk[2].buffer[unk[3]] = DPTR + OFFSET
		end
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
	if token.group[2].t == "COMPLETE_VALUE_GROUP" then
		dumpValueGroup(token.group[2],token)
	else
		extractConst(token.group[2],token,1)
	end
	return token.buffer,#token.buffer
end

local function smallConstTMatch(const_tokens,token_pattern)
	if #const_tokens ~= #token_pattern then
		return false
	end
	for ind,const in ipairs(const_tokens) do
		print(const.group[1].t)
		local i = token_pattern[ind]
		if const.group[1].t == i or i == "!ANY!" then
		else
			return false
		end
	end
	return true
end

function keyword_handlers.COMPLETE_OFFSET(token)
	OFFSET = extractConst(token.group[2])
	print(OFFSET)
	if OFFSET == nil then
		error("Invalid offset generated from constant ["..token.group[2].v)
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
	end
end

local macros = {}

function macros.DEFINE(ll_tokens,hl_tokens)
	local arg1 = ll_tokens[1]
	local arg2 = ll_tokens[2]
	if arg2.t == "NUMBER" then
		ident_lookups[arg1.v] = tonumber(arg2.v)
	end
	if arg1.t == "IDENT" then
		ident_lookups[arg1.v] = arg2.v
	end

end

function keyword_handlers.COMPLETE_MACRO(token)
	local args = {}
	for str in string.gmatch(token.v,"[^%s#]+") do
		table.insert(args,str)
	end
	local fn = string.upper(table.remove(args,1))
	if not macros[fn] then
		tokenError("Invalid Macro ("..fn..")",token)
	end
	local tokens,ll_tokens = zasmTokenize(table.concat(args," "),true)
	local succ,err = pcall(macros[fn],ll_tokens,tokens)
	if not succ then
		tokenError("Macro Error:"..err,token)
	end
end

function ZCAssemble(str,fname,writeByte,successCB,errorCB)
	errorCallback = errorCB
	errFname = fname
	local benchtime = SysTime()
	local tokens = zasmTokenize(str)
	unknown_ident_dependents = {}
	idents = {}
	ident_lookups = {}
	DPTR = 0
	OFFSET = 0
	OUTPUT_BUFFER = {}

	local err = false
	-- fixed size allocations, pre-buffer size and constant determination
	for k,token in ipairs(tokens) do
		local t = token.t
		local b,s
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
				err = true
				tokenError(b,token)
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

	for _,token in ipairs(tokens) do
		if token.buffer then
			-- print("output ",token.t)
			local dptr = token.DPTR
			if token.size ~= #token.buffer then
				err = true
				tokenError("Missing values in "..token.t.." (".._..")",0)
				break
			end
			for ind,byte in pairs(token.buffer) do 
				-- print(dptr+ind,byte)
				-- sleep(1)
				if not byte then
					err = true
					tokenError(token.t.."(",_,")".." at pos "..dptr+ind.." has an undefined/invalid constant",0)
					break
				end
				OUTPUT_BUFFER[dptr+ind] = byte
			end
		end
	end
	if err then return 0,{},{},{},{},{},{},{},{} end

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
		Labels[k] = {
			Pointer = v
	}
	end
	print((SysTime()-benchtime)*1000)
	-- return these to the GC
	unknown_ident_dependents = {}
	idents = {}
	ident_lookups = {}
	DPTR = 0
	OFFSET = 0
	OUTPUT_BUFFER = {}
	errorCallback = nil
	successCB(warns)
	-- CPULib.Debugger.MemoryVariableByIndex,
    -- CPULib.Debugger.MemoryVariableByName,
    -- CPULib.Debugger.Labels,
    -- CPULib.Debugger.PositionByPointer,
    -- CPULib.Debugger.PointersByLine 
	return size,warns,MemoryVariableByIndex,MemoryVariableByName,Labels,PositionByPointer,PointersByLine
end