tinyToken = {}

local smatch = string.match


-- case insensitivizer
function tinyToken.fuzz(str,barrier,paren)
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

-- case sensitivizer
function tinyToken.unfuzz(instr,upper)
	local len = #instr
	local str = ""
	for letter in string.gmatch(instr,"%[([a-zA-Z])[a-zA-Z]+%]") do
		str = str .. letter
	end
	if upper then
		str = str:upper()
	else
		str = str:lower()
	end
	return str
end

--error wrapper
local function tokenError(tokenizer,msg,token)
	tokenizer.error = true
	if not token then
		error("Attempted to use tokenError with no/invalid token?",2)
	end
	local msg = string.format("[line: %d column: %d] %s",token.line or 1,token.s or 1,msg)
	if tokenizer.errorCallback then
		tokenizer.errorCallback(msg,{
			Line = token.line or 1,
			Col = token.s or 1,
			File = tokenizer.errFname
		})
	else
		error(msg,0)
	end
end


local function optimizeTokens(tokenizer,TOKEN_PATTERNS,TOKEN_ORDER,HL_TOKEN_PATTERNS,HL_TOKEN_ORDER)
	local function getAllTokenMatches(filter)
		local matches = {}
		for ind, patterns in ipairs(HL_TOKEN_ORDER) do
			if smatch(HL_TOKEN_PATTERNS[ind], filter) then
				table.insert(matches, HL_TOKEN_PATTERNS[ind])
			end
		end
		for ind, patterns in ipairs(TOKEN_ORDER) do
			if smatch(TOKEN_PATTERNS[ind], filter) then
				table.insert(matches, TOKEN_PATTERNS[ind])
			end
		end
		return matches
	end
	local reverse_table = {}
	for k, v in pairs(HL_TOKEN_PATTERNS) do
		for ind, i in ipairs(HL_TOKEN_ORDER) do
			if i == v then
				reverse_table[ind] = k
				break
			end
		end
	end
	for k, v in pairs(reverse_table) do
		HL_TOKEN_PATTERNS[k] = v
	end
	local present_tokens = {}
	local modified = false
	for tname, hl_token in ipairs(HL_TOKEN_ORDER) do
		::start_over::
		modified = false
		present_tokens = {}
		for _, pattern in ipairs(hl_token) do
			for ind, token_type in ipairs(pattern) do
				if smatch(token_type, "[%.%*]+") then
					local f = getAllTokenMatches(token_type)
					modified = true
					local r = table.remove(hl_token, _)
					for find, i in ipairs(f) do
						local t = {}
						for k, v in ipairs(r) do
							if k == ind then
								t[k] = i
							else
								t[k] = v
							end
						end
						table.insert(hl_token, _, t)
					end
					break
				end
				present_tokens[token_type] = true
			end
			if modified then
				break
			end
		end
		if modified then
			goto start_over
		end
		for k, v in pairs(present_tokens) do
			if k == "!ANY!" then
				hl_token.required = true
				break
			end
		end
		hl_token.present_tokens = present_tokens
	end
	local id = 1
	local tokenLookup = {}
	local ll_tokens = {}
	local ll_token_order = {}
	for ind,v in ipairs(TOKEN_ORDER) do
		ll_tokens[ind] = v
		ll_token_order[ind] = v
		tokenLookup[id] = TOKEN_PATTERNS[ind]
		tokenLookup[TOKEN_PATTERNS[ind]] = id
		id = id + 1
	end
	local hl_tokens = {}
	local hl_token_order = {}
	_OPT_LL_TOKEN_PATTERNS = ll_tokens
	_OPT_LL_TOKEN_ORDER = ll_tokens
	_OPT_HL_TOKEN_PATTERNS = hl_tokens
	_OPT_HL_TOKEN_ORDER = hl_token_order
	_OPT_TLOOKUP = tokenLookup
	tokenLookup["!ANY!"] = -1
	tokenLookup["!BREAK!"] = -2
	tokenLookup["!NEWLINE!"] = -3
	tokenLookup["!PREV!"] = -4
	tokenLookup[-1] = "!ANY!"
	tokenLookup[-2] = "!BREAK!"
	tokenLookup[-3] = "!NEWLINE!"
	tokenLookup[-4] = "!PREV!"
	-- Must be done separately.
	for ind,patterns in ipairs(HL_TOKEN_ORDER) do
		local name = HL_TOKEN_PATTERNS[ind]
		if not tokenLookup[name] then
			tokenLookup[name] = id
			tokenLookup[id] = name
			id = id + 1
		end
	end
	local longestSequence = 0
	for ind,patterns in ipairs(HL_TOKEN_ORDER) do
		local name = HL_TOKEN_PATTERNS[ind]
		local npatternset = {}
		hl_token_order[ind] = npatternset
		for pind,pattern in ipairs(patterns) do
			local npattern = {}
			npatternset[pind] = npattern
			local len = 0
			for tind,token in ipairs(pattern) do
				if not tokenLookup[token] then
					hl_tokens[id] = token
					hl_tokens[token] = id
					tokenLookup[id] = token
					tokenLookup[token] = id
					id = id + 1
				end
				npattern[tind] = tokenLookup[token]
				len = len + 1
			end
			if len > longestSequence then longestSequence = len end
			npattern.length = len
		end
		npatternset.required = patterns.required
		npatternset.present_tokens = {}
		for k,v in pairs(patterns.present_tokens) do
			npatternset.present_tokens[tokenLookup[k]] = true
		end
	end
	local errorTokens = {}
	for k,v in pairs(tokenizer.ERROR_TOKENS) do
		errorTokens[tokenLookup[k]] = v
	end
	tokenizer._OPT_LL_TOKEN_PATTERNS = ll_tokens
	tokenizer._OPT_LL_TOKEN_ORDER = ll_tokens
	tokenizer._OPT_HL_TOKEN_PATTERNS = hl_tokens
	tokenizer._OPT_HL_TOKEN_ORDER = hl_token_order
	tokenizer._OPT_TLOOKUP = tokenLookup
	tokenizer._OPT_ERROR_TOKENS = errorTokens
	tokenizer._OPT_LONGEST_SEQ = longestSequence
end

local function getToken(TOKEN_ORDER,TOKEN_PATTERNS,opt,str)
	for ind, patternset in ipairs(TOKEN_ORDER) do
		for _, pattern in ipairs(patternset) do
			local s, res, e, e2 = str:match("^%s*()(" .. pattern .. ")()")
			if res then
				if type(e) == "string" then
					res = e
					e = e2
				end
				return {
					t = opt and ind or TOKEN_PATTERNS[ind],
					v = res,
					vup = res:upper(),
					vlow = res:lower(),
					s = s,
					e = e
				}
			end
		end
	end
end
local function tokenizerMain(self,str,split)
	local
	HL_TOKEN_ORDER,HL_TOKEN_PATTERNS,
	TOKEN_PATTERNS,TOKEN_ORDER,
	ERROR_TOKENS,
	tokenError,tokenLookup,longestSequence = self._OPT_HL_TOKEN_ORDER,self._OPT_HL_TOKEN_PATTERNS,
	self._OPT_LL_TOKEN_PATTERNS,self._OPT_LL_TOKEN_ORDER,self._OPT_ERROR_TOKENS,
	self.tokenError,self._OPT_TLOOKUP,self._OPT_LONGEST_SEQ
	local _BREAK,_ANY,_PREV,_NEWLINE = tokenLookup["!BREAK!"],tokenLookup["!ANY!"],tokenLookup["!PREV!"],tokenLookup["!NEWLINE!"]
	local LL_TOKEN_COUNT = #TOKEN_ORDER
	local optimized = true
	local s,e
	local tokenstack = {}
	local lines = 0
	local ll_bench = os.epoch("local")
	for word in string.gmatch(str, "[^\n]*\n?") do
		lines = lines + 1
		::reword::
		s, e = 1, (#word) + 1
		local t = getToken(TOKEN_ORDER,TOKEN_PATTERNS,optimized,word)
		if t then
			table.insert(tokenstack, t)
			t.line = lines
			if t.e < e then
				word = string.sub(word, t.e, e)
				goto reword
			end
		end
		table.insert(tokenstack, {
			t = _NEWLINE,
			v = "\n",
			vup = "\n",
			vlow = "\n",
			s = s,
			e = e
		})
	end
	ll_bench = os.epoch("local") - ll_bench
	local ll_tokens = {}
	if split then
		for ind, i in ipairs(tokenstack) do
			ll_tokens[ind] = i
		end
	end
	local cur_token = 0
	local iterations = 0
	local ll_token_amt = #tokenstack
	local target = ll_token_amt
	local hl_bench = os.epoch("local")
	while true do
		for nind, patterns in ipairs(HL_TOKEN_ORDER) do
			local broken = false
			do
				local checked_token = tokenstack[cur_token + 1]
				if checked_token and (not patterns.present_tokens[checked_token.t]) and (not patterns.required) then
					goto skip
				end
			end
			for _, pattern in ipairs(patterns) do
				local match = true
				local skip_one = false
				for ind, token in ipairs(pattern) do
					local grabbed_token = tokenstack[cur_token + ind]
					if skip_one then
						skip_one = false
						goto skip
					end
					if token == _BREAK or (not grabbed_token) then
						match = false
						broken = true
						break
					end
					if token == _PREV then
						local prev = tokenstack[cur_token + ind - 1]
						local pat = pattern[ind + 1]
						if not prev or pat ~= prev.t and pat ~= _ANY then
							match = false
							break
						end
						skip_one = true
						goto skip
					end
					if not patterns.present_tokens[grabbed_token.t] and (not patterns.required) or token ~= _ANY and grabbed_token.t ~= token then
						match = false
						break
					end
					::skip::
				end
				if broken then
					break
				end
				if match then
					local hl_token = {
						t = nind+LL_TOKEN_COUNT,
						group = {},
						vup = "",
						v = "",
						vlow = ""
					}
					for i = cur_token + 1, cur_token + (pattern.length) do
						local grabbed_token = table.remove(tokenstack, cur_token + 1)
						hl_token.v = hl_token.v .. " " .. grabbed_token.v
						table.insert(hl_token.group, grabbed_token)
					end
					hl_token.line = hl_token.group[1].line
					hl_token.s = hl_token.group[1].s
					hl_token.vup = hl_token.v:upper()
					hl_token.vlow = hl_token.v:lower()
					if ERROR_TOKENS[hl_token.t] then
						tokenError(ERROR_TOKENS[hl_token.t], hl_token)
					end
					table.insert(tokenstack, cur_token + 1, hl_token)
					cur_token = cur_token - longestSequence
					target = target + longestSequence*2
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
	hl_bench = os.epoch("local") - hl_bench
	self.ll_bench = ll_bench
	self.ll_token_amt = ll_token_amt
	self.hl_bench = hl_bench
	self.iterations = iterations
	print("LL Bench:", ll_bench)
	print("LL Bench found", ll_token_amt, "tokens")
	print("HL Bench:", hl_bench)
	print("HL Bench took", iterations, "iterations to complete")
	local renamestack = {}
	for k,v in ipairs(tokenstack) do
		table.insert(renamestack,v)
	end
	while(true) do
		local token = table.remove(renamestack)
		if not token then break end
		if token.group then
			for k,v in ipairs(token.group) do
				table.insert(renamestack,v)
			end
		end
		token.t = tokenLookup[token.t] or token.t
	end
	if split then
		for k,v in ipairs(ll_tokens) do
			table.insert(renamestack,v)
		end
		while(true) do
			local token = table.remove(renamestack)
			if not token then break end
			token.t = tokenLookup[token.t]
		end
		return tokenstack, ll_tokens
	end
	return tokenstack
end

function tinyToken.createTokenizer(ll_tokens,hl_tokens,ll_token_order,hl_token_order,error_tokens,error_messages)
	local tokenizer
	tokenizer = {
		Tokenizer = tokenizerMain,
		Update = function() return optimizeTokens(tokenizer,tokenizer.LL_TOKEN_PATTERNS,tokenizer.LL_TOKEN_ORDER,tokenizer.HL_TOKEN_PATTERNS,tokenizer.HL_TOKEN_ORDER) end,
		tokenError = function(...) return tokenError(tokenizer,...) end,
		LL_TOKEN_ORDER = ll_token_order or {},
		HL_TOKEN_ORDER = hl_token_order or {},
		LL_TOKEN_PATTERNS = ll_tokens or {},
		HL_TOKEN_PATTERNS = hl_tokens or {},
		ERROR_MESSAGES = error_messages or {},
		ERROR_TOKENS = error_tokens or {},
	}
	tokenizer.Update()
	return setmetatable(tokenizer,{
		__call = function (self,...)
			return self:Tokenizer(...)
		end
	})
end