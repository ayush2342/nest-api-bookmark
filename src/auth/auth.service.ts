import { Body, ForbiddenException, Injectable } from "@nestjs/common";
import { PrismaService } from "../prisma/prisma.service";
import { AuthDto } from "./dto";
import * as bcrypt from 'bcrypt';
import { PrismaClientKnownRequestError } from "@prisma/client/runtime/library";
import { JwtService } from "@nestjs/jwt";
import { ConfigService } from "@nestjs/config";


@Injectable()
export class AuthService{
    constructor(private prisma:PrismaService,private jwt:JwtService,private config:ConfigService){}
    
    async signup(dto:AuthDto){

        try{
            const saltRounds = 10;
        const salt = bcrypt.genSaltSync(saltRounds);
        const hash = bcrypt.hashSync(dto.password, salt);

        const user = await this.prisma.user.create({
            data:{
                email:dto.email,
                hash
            }
        })

        return this.signToken(user.id,user.email)

        }catch(error){
            if(error instanceof PrismaClientKnownRequestError)
            {
                if(error.code==='P2002')
                {
                    throw new ForbiddenException('Credentials Taken')
                }
            }
            throw error;

        }
        
    }

    async signin(dto:AuthDto){

        const user = await this.prisma.user.findFirst({
            where:{
                email:dto.email
            }
        })

        if(!user)
            {
                throw new ForbiddenException('Credentials Incorrrect')
            }
        
        const pwMatches = bcrypt.compareSync(dto.password, user.hash);
        if(!pwMatches)
            {
                throw new ForbiddenException('Credentials Incorrrect')
            }

        return this.signToken(user.id,user.email)
        
        
    }
     async signToken(userId:number,email:string):Promise<{access_token:string}>{

        const payload = {
            sub:userId,
            email
        }

        const secret = this.config.get('JWT_SECRET')
        const token = await this.jwt.signAsync(payload,{
            expiresIn:'15m',
            secret
        })
      
      return {
        access_token:token
    }         
    }
}